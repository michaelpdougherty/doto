import math
import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for
from flask_session import Session
import re
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from zipfile import ZipFile

from helpers import apology, login_required, lookup


'''APPLICATION SETUP'''

# Creates UPLOAD_FOLDER if it does not exist
if "files" not in os.listdir(os.path.join(os.getcwd(), "static")):
    os.mkdir("static/files")

# Set files
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static/files/")
REL_UPLOAD_FOLDER = "/static/files/"
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

# Configure application
app = Flask(__name__)

# Set maximum 16MB file upload size
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REL_UPLOAD_FOLDER"] = REL_UPLOAD_FOLDER
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///doto.db")


'''APP ROUTES'''

@app.route("/")
@login_required
def index():
    """Show table of files"""

    id = session.get("user_id")
    username = db.execute("SELECT username FROM users WHERE id = :id", id=id)[0]["username"]

    files = db.execute("SELECT * FROM files WHERE id = :id", id=id)

    length = len(files)

    return render_template("index.html", username=username, files=files, length=length)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            flash("Please enter a username")
            return redirect(request.url)

        # Ensure password was submitted
        password = request.form.get("password")
        if not password:
            flash("Please enter a password")
            return redirect(request.url)

        # Ensure password and confirmation match
        confirmation = request.form.get("confirmation")
        if confirmation != password:
            flash("Passwords do not match")
            return redirect(request.url)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Ensure username does not already exist
        if len(rows) > 0:
            flash("Username is taken")
            return redirect(request.url)

        # Hash password
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Create new user
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)

        # Query database again
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Log user in
        session["user_id"] = rows[0]["id"]

        # Create string id var
        id = str(session["user_id"])

        # Check if user folder exists
        if id not in os.listdir(UPLOAD_FOLDER):
            # Create user upload folder
            os.chdir(UPLOAD_FOLDER)
            os.mkdir(id)

        # Update upload folders
        app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER + id + "/"
        app.config['REL_UPLOAD_FOLDER'] = REL_UPLOAD_FOLDER + id + "/"

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username")
            return redirect(request.url)

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password")
            return redirect(request.url)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username and/or password")
            return redirect(request.url)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Create string id var
        id = str(session["user_id"])

        # Check if user upload folder exists
        if id not in os.listdir(UPLOAD_FOLDER):
            # Create user upload folder
            os.chdir(UPLOAD_FOLDER)
            os.mkdir(id)

        # Update upload folders
        app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER + id + "/"
        app.config["REL_UPLOAD_FOLDER"] = REL_UPLOAD_FOLDER + id + "/"

        # Remove zips
        removeZips(app.config["UPLOAD_FOLDER"], f"{request.form.get('username')}.zip")

        # Redirect user to home page
        flash("Welcome, " + request.form.get("username"))
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Upload files"""

    id = session.get("user_id")

    # User reached route via GET
    if request.method == "GET":
        return render_template("upload.html")

    # User reached route via POST
    else:

        # Ensure user submitted a file
        if 'file' not in request.files:
            flash("No file submitted")
            return redirect(request.url)

        # Get uploaded files
        uploaded_files = request.files.getlist("file")
        files_submitted = len(uploaded_files)
        files_uploaded = 0
        files = []

        # Save files to directory
        for file in uploaded_files:
            if file.filename and allowed_file(file.filename):
                # Secure filename
                filename = secure_filename(file.filename)

                # Create upload path
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Ensure no duplicate filenames regex: ^(.*?)\((\d+)\)\.([a-zA-Z0-9]*)$
                uniq = 1
                while os.path.exists(path):
                    # Split filename into "x(y).z"
                    parenth = re.match(r"^(.*?)\((\d+)\)\.([a-zA-Z0-9]*)$", filename)

                    # Filename has "(y).z" pattern
                    if parenth:
                        parenth = parenth.groups()
                        filename = parenth[0] + "(" + str(uniq) + ")." + parenth[2]

                    # Filename does not have "(y).z" pattern
                    else:
                        noParenth = re.match(r"^(.*?)\.([a-zA-Z0-9]*)$", filename).groups()
                        filename = noParenth[0] + "(" + str(uniq) + ")." + noParenth[1]

                    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    uniq += 1

                # Save file
                file.save(path)

                # Get file size
                size = os.path.getsize(path)

                # Get relative path
                path = app.config["REL_UPLOAD_FOLDER"] + filename

                # Get filename without extension
                extension = re.match(r"^(.*?)(\.[a-zA-Z0-9]*)$", filename)
                extension = extension.groups()
                displayName = extension[0]

                # Insert file into SQL database
                db.execute("INSERT INTO files (id, name, size, path, displayName) VALUES (:id, :filename, :size, :path, :displayName)", id=id, filename=filename, size=size, path=path, displayName=displayName)

                # Increment message
                files.append(filename)
                files_uploaded += 1

        if files_uploaded > 0:
            first_filename = files[0]
        else:
            flash("Error: No files uploaded - Doto only accepts images less than 16MB")
            return redirect("/")

        if files_uploaded < files_submitted:
            flash(f"Error: {files_uploaded} / {files_submitted} files uploaded - Doto only accepts images less than 16MB")
        elif files_uploaded == 1:
            flash(f"{first_filename} uploaded")
        else:
            flash(f"{files_uploaded} files uploaded")
        return redirect(url_for('uploaded_file', filename=files[0]))


@app.route("/get/<filename>", methods=["GET"])
@login_required
def get(filename):
    '''Get files'''

    # Get user ID
    id = session.get("user_id")

    # Get ALL user files
    files = db.execute("SELECT name, path FROM files WHERE id = :id", id=id)

    lastIndex = len(files) - 1

    # Get file by filename
    if filename == "browse":
        file = files[0]
        index = 0
    else:
        file = db.execute("SELECT * FROM files WHERE name = :name AND id = :id", name=filename, id=id)[0]
        index = files.index(file)

    data = {
        'index': index,
        'lastIndex': lastIndex,
        'files': files
    }

    return jsonify(data)


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    '''File browser'''

    # Get user ID
    id = session.get("user_id")

    # Get ALL user files
    files = db.execute("SELECT name, favorited, path, displayName FROM files WHERE id = :id", id=id)

    # Determine number of files
    length = len(files)

    # Determine lastIndex of files
    lastIndex = length - 1

    # Get file by filename
    if filename == "browse":
        if len(files) == 0:
            return redirect("/")
        file = files[0]
        index = 0
    else:
        file = db.execute("SELECT * FROM files WHERE name = :name AND id = :id", name=filename, id=id)[0]
        index = find(files, "name", filename)

    data = {
        'index': index,
        'lastIndex': lastIndex,
        'files': files
    }

    return render_template("file.html", index=index, length=length, lastIndex=lastIndex, files=files)


@app.route("/buttons/<action>", methods=["POST"])
def buttons(action):
    id = session.get("user_id")

    # Get submitted files
    filenames = request.form.get("filenames").split(",")

    # Favorite action
    if action == "favorite":
        for name in filenames:
            currentVal = db.execute("SELECT favorited FROM files WHERE id=:id and name=:name", id=id, name=name)[0]['favorited']
            if currentVal == 'true':
                boolean = 'false'
            else:
                boolean = 'true'
            db.execute("UPDATE files SET favorited = :boolean WHERE id = :id AND name = :name", boolean=boolean, id=id, name=name)
        if len(filenames) == 0:
            flash("Error: no filenames")
        if len(filenames) == 1:
            first_filename = filenames[0]
            if boolean == 'true':
                flash(f"{first_filename} favorited")
            else:
                flash(f"{first_filename} unfavorited")
        else:
            flash(f"{len(filenames)} files (un)favorited")

    # Rename action
    elif action == "rename":
        newFilenames = eval(request.form.get("newFilenames"))
        renamedFiles = 0
        for i in newFilenames:
            if i['value']:
                filename = i['key']
                newDisplayName = i['value']

                # Break filename into displayName and extension
                matchedFilename = re.match(r"^(.*?)(\.[a-zA-Z0-9]*)$", filename)
                matchedFilename = matchedFilename.groups()

                displayName = matchedFilename[0]
                extension = matchedFilename[1]

                newFilename = secure_filename(newDisplayName + extension)

                # Ensure new filename does not already exist
                if len(db.execute("SELECT * FROM files WHERE id = :id AND displayName = :newDisplayName", id=id, newDisplayName=newDisplayName)) != 0:
                    flash(f"Filename {newDisplayName} already exists")
                    return redirect("/uploads/" + filename)
                else:
                    db.execute("UPDATE files SET displayName = :newDisplayName, name = :newFilename, path = :path WHERE id = :id AND name = :filename", newDisplayName=newDisplayName, newFilename=newFilename, id=id, filename=filename, path=os.path.join(app.config['REL_UPLOAD_FOLDER'], newFilename))
                    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    target = os.path.join(app.config['UPLOAD_FOLDER'], newFilename)
                    os.rename(path, target)
                    renamedFiles += 1
        if renamedFiles == 0:
            flash("Error: no files renamed")
        elif renamedFiles == 1:
            flash(f"Renamed {newFilenames[0]['key']} to {newFilenames[0]['value']}")
        elif renamedFiles > 1:
            flash(f"Renamed {renamedFiles} files")

    # Download action
    elif action == "download":
        # Get upload folder
        directory = app.config["UPLOAD_FOLDER"]
        os.chdir(directory)
        # Download one file
        if len(filenames) == 1:
            return send_from_directory(directory, filenames[0], as_attachment=True)
        # Zip multiple files, deleting any existing zips
        else:
            username = db.execute("SELECT username FROM users WHERE id=:id", id=id)[0]['username']
            zipName = f"{username}.zip"
            if zipName in os.listdir(directory):
                os.remove(zipName)
            with ZipFile(zipName,'w') as zip:
                for file in filenames:
                    zip.write(file)
                ZipFile.close(zip)
            return send_from_directory(directory, zipName, as_attachment=True)

    # Delete action
    elif action == "delete":
        for name in filenames:
            db.execute("DELETE FROM files WHERE name = :name AND id = :id", name=name, id=id)
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], name))
        if len(filenames) == 0:
            flash("Error: no files deleted")
        elif len(filenames) == 1:
            flash(f"Deleted {filenames[0]}")
        elif len(filenames) > 1:
            flash(f"Deleted {len(filenames)} files")

    # Unknown action
    else:
        flash("Error: unknown request")

    return redirect("/")


@app.route("/favorite/<filename>/<boolean>", methods=["GET", "POST"])
@login_required
def favorite(filename, boolean):
    '''Favorite file by filename and boolean'''

    # Get user ID
    id = session.get("user_id")

    # User sent data as GET request
    if request.method == "GET":

        # Update file
        db.execute("UPDATE files SET favorited = :boolean WHERE id = :id AND name = :filename", boolean=boolean, id=id, filename=filename)

        if boolean == 'true':
            flash(filename + " favorited")
        else:
            flash(filename + " unfavorited")

        return redirect("/uploads/" + filename)

    else:
        return redirect("/uploads")


@app.route("/rename/<filename>/<newDisplayName>")
@login_required
def rename(filename, newDisplayName):
    '''Rename file by filename and new filename'''
    # Ensure NOT NULL
    if not newDisplayName:
        flash("Please enter a filename")
        return redirect("/uploads/" + filename)

    # Get user ID
    id = session.get("user_id")

    # Break filename into displayName and extension
    matchedFilename = re.match(r"^(.*?)(\.[a-zA-Z0-9]*)$", filename)
    matchedFilename = matchedFilename.groups()

    displayName = matchedFilename[0]
    extension = matchedFilename[1]

    newFilename = secure_filename(newDisplayName + extension)

    # Ensure new filename does not already exist
    if len(db.execute("SELECT * FROM files WHERE id = :id AND displayName = :newDisplayName", id=id, newDisplayName=newDisplayName)) != 0:
        flash(f"Filename {newDisplayName} already exists")
        return redirect("/uploads/" + filename)
    else:
        db.execute("UPDATE files SET displayName = :newDisplayName, name = :newFilename, path = :path WHERE id = :id AND name = :filename", newDisplayName=newDisplayName, newFilename=newFilename, id=id, filename=filename, path=os.path.join(app.config['REL_UPLOAD_FOLDER'], newFilename))
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        target = os.path.join(app.config['UPLOAD_FOLDER'], newFilename)
        os.rename(path, target)

        flash(f"File {displayName} renamed to {newDisplayName}")
        return redirect("/uploads/" + newFilename)


@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    '''Download file by filename'''
    directory = app.config['UPLOAD_FOLDER']
    return send_from_directory(directory, filename, as_attachment=True)


@app.route('/delete/<filename>')
@login_required
def delete(filename):
    '''Delete a file by filename'''
    id = session.get("user_id")
    db.execute("DELETE FROM files WHERE id=:id AND name=:filename", id=id, filename=filename)
    target = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    os.remove(target)
    return redirect("/uploads/browse")


def removeZips(directory, zipName):
    if zipName in os.listdir(directory):
        os.remove(zipName)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return render_template("error.html", name=e.name, code=e.code)


def allowed_file(filename):
    '''Determine if filename has an allowed extension'''
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_path(filename):
    '''Get relative path of a file by filename'''
    return app.config['REL_UPLOAD_FOLDER'] + filename


def find(lst, key, value):
    '''Index file in files'''
    for i, dic in enumerate(lst):
        if dic[key] == value:
            return i
    return -1


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
