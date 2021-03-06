import os, datetime, time, random, json, uuid, chartkick, base64, hashlib
from os.path import splitext
from flask import redirect, render_template, url_for, flash, request, Flask, send_file, jsonify

from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm.exc import NoResultFound
from flask.ext.script import Manager, Shell
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import LoginManager, login_required, login_user, UserMixin, logout_user, current_user
from werkzeug import secure_filename

import config
from sanicap import sanitize
from forms import LoginForm, EditTags, ProfileForm, AddUser, EditUser, TempPasswordForm, SanitizeForm
from flask.ext.migrate import Migrate, MigrateCommand
from flask_socketio import SocketIO, emit
from pcap_helper import get_capture_count, decode_capture_file_summary, get_packet_detail
from pysharksniffer import PysharkSniffer
from pyshark.tshark.tshark import get_tshark_interfaces, get_tshark_interfaces_list
import threading
from database import db
from models import User, TraceFile, Log, Tag, Template

basedir = os.path.abspath(os.path.dirname(__file__))

## app setup
app = Flask(__name__)
db.app = app
db.init_app(app)
manager = Manager(app)
socketio = SocketIO(app)
bootstrap = Bootstrap(app)

app.jinja_env.add_extension("chartkick.ext.charts")
#app.config.from_object(os.environ['APP_SETTINGS'])
app.config.from_object("config.DevelopmentConfig")
ALLOWED_EXTENSIONS = ['pcap','pcapng','cap']
UPLOAD_FOLDER = os.path.join(basedir, 'static/tracefiles/')

def format_comma(value):
    return "{:,.0f}".format(value)
app.jinja_env.filters['format_comma'] = format_comma

migrate = Migrate(app, db)
## Login Manager
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

sniffer = None
deviceStatus = {}
isRunning = False
isIRouterRunning = False
isERouterRunning = False
isIFirewallRunning = False
isEFirewallRunning = False
isSwitchRunning = False
templates = []

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def get_uuid():
    #return base64.b64encode(hashlib.sha256( str(random.getrandbits(256)) ).digest(), random.choice(['rA','aZ','gQ','hH','hG','aR','DD'])).rstrip('==')
    return hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()

# Create DB tables and default admin user if they don't exist
def init_db(username='admin', password='chox'):
    print('Initizializing DB')
    db.create_all()
    admin = User(username=username, password=password, role='admin', token=get_uuid())
    db.session.add(admin)
    print('User \'%s\' added with password: %s' % (username, password))
    db.session.commit()

def allowed_file(filename):
    return '.' in filename and (filename.split('.')[-1] in ALLOWED_EXTENSIONS)

def log(level, description):
    note = Log(timestamp=datetime.datetime.now(), level=level.upper(), description=description)
    db.session.add(note)
    db.session.commit()

@app.route('/login/', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(request.args.get('next') or url_for('login'))

        if user.temp_password:
            return redirect(url_for('home'))
        else:
            return redirect(request.args.get('next') or url_for('home'))

    else:
        return render_template('login.html', form=form)

@app.route('/logout/', methods=['GET','POST'])
def logout():
    logout_user()
    flash('You have been logged out.', 'warning')
    return redirect(url_for('login'))

@app.route('/', methods=['GET','POST']) 
@login_required
def home():

    form = TempPasswordForm()
    templates = Template.query.all()

    if form.validate_on_submit():

        user = User.query.filter_by(id=current_user.id).one()

        if user.verify_password(form.temp_password.data):
            user.password = form.new_password1.data
        else:
            flash('Current password is not correct.', 'danger')
            return redirect(url_for('home'))

        user.temp_password = False
        db.session.commit()


        flash('Password has been changed.', 'success')
        return redirect(url_for('home'))

    else:
        
        global deviceStatus
        global isRunning
        global isIRouterRunning
        global isERouterRunning
        global isIFirewallRunning
        global isEFirewallRunning
        global isSwitchRunning

        deviceStatus['irouter'] = isIRouterRunning
        deviceStatus['erouter'] = isERouterRunning
        deviceStatus['ifirewall'] = isIFirewallRunning
        deviceStatus['efirewall'] = isEFirewallRunning
        deviceStatus['swtch'] = isSwitchRunning
        deviceStatus['livecapture'] = isRunning

        tag = request.args.get('tag')

        if tag:
            traceFiles = [TraceFile.query.filter_by(id=x.file_id).first() for x in Tag.query.filter_by(name=tag).all()]
            # For future use of filtering just one users' files
            # traceFiles = [TraceFile.query.filter_by(user_id=current_user.id).filter_by(id=x.file_id).first() for x in Tag.query.filter_by(name=tag).all()]
        else:
            traceFiles = TraceFile.query.filter_by(status=1).all()
            # For future use of filtering just one users' files
            # traceFiles = TraceFile.query.filter_by(user_id=current_user.id).all()

        tags = set([x.name for x in Tag.query.all()])



        return render_template('home.html', form=form, data=deviceStatus, traceFiles=traceFiles, tags=tags, templates=templates)

@app.route('/pcap', methods=['GET', 'POST'])
@login_required
def pcap():
    templates = Template.query.all()
    tag = request.args.get('tag')

    if tag:
        traceFiles = [TraceFile.query.filter_by(id=x.file_id).first() for x in Tag.query.filter_by(name=tag).all()]
        # For future use of filtering just one users' files
        # traceFiles = [TraceFile.query.filter_by(user_id=current_user.id).filter_by(id=x.file_id).first() for x in Tag.query.filter_by(name=tag).all()]
    else:
        traceFiles = TraceFile.query.filter_by(status=1).all()
        # For future use of filtering just one users' files
        # traceFiles = TraceFile.query.filter_by(user_id=current_user.id).all()

    tags = set([x.name for x in Tag.query.all()])

    return render_template('pcap.html', templates=templates, traceFiles=traceFiles, tags=tags)

@app.route('/captures/<file_id>')
@login_required
def captures(file_id):

    tagsForm = EditTags(prefix='tags')
    sanitizeForm = SanitizeForm(prefix='sanitize')

    display_filter = request.args.get('display_filter')

    traceFile = TraceFile.query.get_or_404(file_id)

    templates = Template.query.all()

    try:
        tagsForm.tags.data = ', '.join(x.name for x in Tag.query.filter_by(file_id=file_id).all())
    except NoResultFound:
        tagsForm.tags.data = ''

    display_count, details = decode_capture_file_summary(traceFile, display_filter)

    try:
        basestring
    except NameError:
        basestring = str

    if isinstance(details, basestring):
        flash(details, 'warning')
        return render_template('captures.html', traceFile=traceFile, tagsForm=tagsForm, templates=templates, sanitizeForm=sanitizeForm, display_count=display_count)
    
    tags = set([x.name for x in Tag.query.all()])

    return render_template('captures.html', traceFile=traceFile, templates=templates, tagsForm=tagsForm, sanitizeForm=sanitizeForm, display_count=display_count, details=details, tags=tags)


@app.route('/captures/<file_id>/packetDetail/<int:number>')
def packet_detail(file_id, number):

    traceFile = TraceFile.query.get_or_404(file_id)

    return get_packet_detail(traceFile, number), 200

@app.route('/captures/<file_id>/sanitize', methods=['POST'])
@login_required
def sanitize_packet(file_id):

    data = json.loads(request.data)
    
    traceFile = TraceFile.query.get_or_404(file_id)

    timestamp = datetime.datetime.now().strftime('%y%m%d-%H%m%S')
    uuid_filename = '.'.join([str(uuid.uuid4()),traceFile.filetype])
    
    print(data['sequential'])

    try:
        sanitize(filepath_in = os.path.join(UPLOAD_FOLDER, traceFile.filename), 
            filepath_out = os.path.join(UPLOAD_FOLDER, uuid_filename),
            sequential= data['sequential'],
            ipv4_mask= int([0, data['ipv4_mask']][len(data['ipv4_mask']) > 0]),
            ipv6_mask= int([0, data['ipv6_mask']][len(data['ipv6_mask']) > 0]),
            mac_mask=    int([0, data['mac_mask']][len(data['mac_mask']) > 0]),
            start_ipv4= ['10.0.0.1', data['start_ipv4']][len(data['start_ipv4']) > 0],
            start_ipv6= ['2001:aa::1', data['start_ipv6']][len(data['start_ipv6']) > 0],
            start_mac=  ['00:aa:00:00:00:00', data['start_mac']][len(data['start_mac']) > 0]
            )
    except Exception as e:
        flash('Sanitizing - %s: %s.%s' % (e.message, traceFile.name, traceFile.filetype), 'danger')
        log('error', 'Sanitizing - %s: %s.%s' % (e.message, traceFile.name, traceFile.filetype))

    new_file = TraceFile(id=str(uuid.uuid4())[:8],
        name=secure_filename(traceFile.name + '_sanitized_' + timestamp),
        user_id = current_user.id,
        filename = uuid_filename,
        filetype = traceFile.filetype,
        filesize = os.path.getsize(os.path.join(UPLOAD_FOLDER, uuid_filename)),
        packet_count = get_capture_count(uuid_filename),
        date_added = datetime.datetime.now()
        )


    db.session.add(new_file)
    db.session.commit()
    db.session.refresh(new_file)

    new_tag = Tag(name='Sanitized', file_id=new_file.id)
    db.session.add(new_tag)
    db.session.commit()

    flash('File sanitized: %s.%s' % (new_file.name, traceFile.filetype) , 'success')
    log('info','File sanitized by \'%s\': %s.' % (current_user.username, new_file.name))

    return jsonify({'Result': 'Success'}), 200

@app.route('/users/', methods=['GET', 'POST'])
@login_required
def users():
    form = AddUser()

    if form.validate_on_submit():
        if current_user.role != 'admin':
            flash('You are not permitted to add users.', 'warning')
            return redirect(url_for('users'))

        if form.role.data not in ['admin']:
            flash('%s is not a valid role.' % form.role.data, 'warning')
            return redirect(url_for('users'))

        user = User(username=form.username.data, 
            password=form.password.data, 
            role=form.role.data, 
            temp_password=True,
            token = get_uuid())

        db.session.add(user)
        db.session.commit()

        flash('User %s has been added.' % user.username, 'success')
        return redirect(url_for('users'))

    else:

        if current_user.role != 'admin':
            flash('You are not permitted to edit users.', 'warning')
            return redirect(url_for('dashboard'))

        templates = Template.query.all()

        users = User.query.order_by(User.id).all()
        return render_template('users.html', templates=templates, form=form, users=users)

@app.route('/users/<user_id>', methods=['GET', 'POST'])
@login_required
def user(user_id):
    form = EditUser()

    if form.validate_on_submit():
        if current_user.role != 'admin':
            flash('You are not permitted to edit users.', 'warning')
            return redirect(url_for('users'))

        if form.role.data not in ['admin']:
            flash('%s is not a valid role.' % form.role.data, 'warning')
            return redirect(url_for('users'))

        user = User.query.get_or_404(user_id)
        user.role = form.role.data
        db.session.commit()
        
        flash('Changes to %s have been made.' % user.username, 'success')
        return redirect(url_for('users'))

    else:

        if current_user.role != 'admin':
            flash('You are not permitted to edit users.', 'warning')
            return redirect(url_for('dashboard'))

        user = User.query.get_or_404(user_id)

        form.role.data = user.role

        templates = Template.query.all()

        return render_template('users.html', templates=templates, form=form, user=user)

@app.route('/users/<user_id>/delete/')
@login_required
def delete_user(user_id):

    name = User.query.get_or_404(user_id).username
    User.query.filter_by(id=user_id).delete()

    db.session.commit()

    log('info','Deleting user: %s' % name)

    flash('User %s has been deleted' % name, 'success')
    return redirect('users')

@app.route('/profile/', methods=['GET', 'POST'])
@login_required
def profile():

    form = ProfileForm()

    if form.validate_on_submit():

        user = User.query.filter_by(username=current_user.username).one()

        user.email = form.email.data

        if form.new_password1.data:
            if user.verify_password(form.current_password.data):
                user.password = form.new_password1.data
            else:
                db.session.commit()
                flash('Current password is not correct.', 'danger')
                return redirect(url_for('profile'))

        db.session.commit()

        flash('Profile changes saved.', 'success')
        return redirect(url_for('profile'))

    else:

        user = User.query.filter_by(username=current_user.username).one()
        
        form.email.data = user.email

        templates = Template.query.all()

        return render_template('profile.html', templates=templates, form=form)


@app.route('/api/v1/<token>/upload', methods=['POST', 'PUT'])
def api_upload_file(token):
    print('!!!!!!!!!!!!!!!!!!!!!!!')
    try:
        user = User.query.filter_by(token=token).one()
    except NoResultFound:
        return json.dumps({"status":404,"exceptions":["API Token is missing or invalid"]}), 404

    if request.method == 'POST':
        traceFile = request.files['file']
        filename = traceFile.filename
        filetype = splitext(filename)[1].strip('.')
        uuid_filename = '.'.join([str(uuid.uuid4()),filetype])
        traceFile.save(os.path.join(UPLOAD_FOLDER, uuid_filename))

    else:
        filename = request.args.get('filename')
        filetype = splitext(filename)[1].strip('.')
        uuid_filename = '.'.join([str(uuid.uuid4()),filetype])
        with open(os.path.join(UPLOAD_FOLDER, uuid_filename), 'w') as f:
            f.write(request.stream.read())

    if allowed_file(filename):

        new_file = TraceFile(id=str(uuid.uuid4())[:8],
            name=secure_filename(splitext(filename)[0]),
            user_id = user.id,
            filename = uuid_filename,
            filetype = filetype,
            filesize = os.path.getsize(os.path.join(UPLOAD_FOLDER, uuid_filename)),
            packet_count = get_capture_count(uuid_filename),
            date_added = datetime.datetime.now(),
            status=1
            )

        db.session.add(new_file)
        db.session.commit()
        db.session.refresh(new_file)

        #add tags
        if request.form.getlist('additional_tags'):
            for tag in request.form.getlist('additional_tags')[0].split(','):
                if tag.strip(',') != '':
                    new_tag = Tag(name = tag.strip(','), file_id=new_file.id)
                    db.session.add(new_tag)

        db.session.commit()

        log('info','File uploaded by \'%s\': %s.' % (user.username, filename))
        return json.dumps({"filename": filename,"id":new_file.id}), 202

    else:
        os.remove(os.path.join(UPLOAD_FOLDER, uuid_filename))
        return json.dumps({"status":406,"exceptions":["Not a valid file type. (pcap, pcapng, cap)"]}), 406

@app.route('/captures/upload')
@login_required
def upload_file():

    api_upload_file(current_user.token)
    
    return redirect(url_for('home'))

#@app.route('/livecapture')
@socketio.on('connect', namespace="/livecapture")
def livecapture_connect():
   print('---connected---')

@app.route('/delete_template', methods=['POST'])
@login_required
def delete_tempalte():

    try:
        params = json.loads(request.form.to_dict()['data'])
        temp_id = params['temp_id']

        template = Template.query.filter_by(id=temp_id).one()
        if template is not None:
            db.session.delete(template)
            db.session.commit()

            templates = Template.query.all()

            return json.dumps({"status":200,"message":[{'type':"success", "message":"Template was deleted."}], "templates_count":len(templates)})
        else:
            return json.dumps({"status":200,"message":[{'type':"warning", "message":"Couldn't find the template"}]})

    except Exception as e:
        return json.dumps({"status":500,"message":[{'type':"danger", "message":"Error occured"}]})

@app.route('/save_template', methods=['POST'])
@login_required
def save_tempalte():

    try:
        params = json.loads(request.form.to_dict()['data'])
        temp_id = params['temp_id']
        name = params['name']
        command = params['command']

        if temp_id == "": #new template
            new_template = Template(name=name, command=command, process_id="", status=0)
            db.session.add(new_template)
            db.session.flush()
            db.session.refresh(new_template)
            db.session.commit()
            id = str(new_template.id)

            data = '<li class="panel" id="main_' + id + '">'
            data += '    <a data-toggle="collapse" data-parent="#templates_container" href="#' +  id + '">' + new_template.name + '</a>'
            data += '    <input type="hidden" class="temp_id" value="' + id + '">'
            data += '    <div class="status_container" id="status_' + id + '" style="position:relative">'
            data += '        <img src="/static/images/green_btn.png" id="" class="shark_btn run" onclick="run(' + id + ')" >'
            data += '        <img src="/static/images/red_btn.png" id="" class="shark_btn stop" onclick="stop(' + id + ')" >'
            data += '    </div>'
            data += '    <ul id="' + id + '" class="collapse template">'
            data += '        <li><div class="form-group">'
            data += '            <div class="form-group">'
            data += '                <input type="text" id="name_' + id + '" class="form-control command" value="' + new_template.name + '">'
            data += '            </div>'
            data += '            <div class="form-group">'
            data += '                <input type="text" id="command_' + id + '" class="form-control command" value="' + new_template.command + '">'
            data += '            </div>'
            data += '            <div class="form-group">'
            data += '                <button class="btn btn-primary" type="button" onclick="save_template(' + id + ')">Save</button>'
            data += '                <button class="btn btn-default" type="button" onclick="delete_template(' + id + ')">Delete</button>'
            data += '            </div>'
            data += '        </div></li>'
            data += '    </ul>'
            data += '</li>'

            templates = Template.query.all()

            return json.dumps({"status":200,"message":[{'type':"success", "message":"New template was added."}], "templates_count":len(templates), "new":data, "template":{'id':id, 'name':new_template.name, 'command':new_template.command}})
        else:
            template = Template.query.filter_by(id=temp_id).one()
            template.name = name
            template.command = command
            db.session.commit()

            id = str(template.id)

            data = '<li class="panel" id="main_' + id + '">'
            data += '    <a data-toggle="collapse" data-parent="#templates_container" href="#' + id + '">' + template.name + '</a>'
            data += '    <input type="hidden" class="temp_id" value="' + id + '">'
            data += '    <div class="status_container" id="status_' + id + '" style="position:relative">'
            data += '        <img src="/static/images/green_btn.png" id="" class="shark_btn run" onclick="run(' + id + ')" >'
            data += '        <img src="/static/images/red_btn.png" id="" class="shark_btn stop" onclick="stop(' + id + ')" >'
            data += '    </div>'
            data += '    <ul id="' + id + '" class="collapse template">'
            data += '        <li><div class="form-group">'
            data += '            <div class="form-group">'
            data += '                <input type="text" id="name_' + id + '" class="form-control command" value="' + template.name + '">'
            data += '            </div>'
            data += '            <div class="form-group">'
            data += '                <input type="text" id="command_' + id + '" class="form-control command" value="' + template.command + '">'
            data += '            </div>'
            data += '            <div class="form-group">'
            data += '                <button class="btn btn-primary" type="button" onclick="save_template(' + id + ')">Save</button>'
            data += '                <button class="btn btn-default" type="button" onclick="delete_template(' + id + ')">Delete</button>'
            data += '            </div>'
            data += '        </div></li>'
            data += '    </ul>'
            data += '</li>'

            return json.dumps({"status":200,"message":[{'type':"success", "message":"Template was saved."}], "new":data, "template":{'id':id, 'name':template.name, 'command':template.command}})
    except Exception as e:
        return json.dumps({"status":500,"message":[{'type':"danger", "message":"Error occured"}]})

@app.route('/stop_capture', methods=['POST'])
@login_required
def stop_capture():
    global sniffer
    global isRunning

    try:
        params = json.loads(request.form.to_dict()['data'])
        temp_id = params['temp_id']

        if temp_id is None or temp_id == '':
            return json.dumps({"status":406,"message":[{'type':"warning", "message":"Templte ID was not specified."}]})

        template = sniffer.getTemplate()

        if template is None:
            return json.dumps({"status":406,"message":[{'type':"warning", "message":"Template isn't started yet."}]})

        if temp_id != template.id:
            return json.dumps({"status":406,"message":[{'type':"warning", "message":template.name + " isn't started yet."}]})

        template_name = template.name

    except Exception as e:
        return json.dumps({"status":406,"message":[{'type':"warning", "message":e}]})

    try:
        [filename, temp_id] = sniffer.stop()

        if filename is not None:
            file = TraceFile.query.filter_by(filename=filename, status=1).first()

            if file is not None:
                file.user_id = current_user.id
                file.filesize = os.path.getsize(os.path.join(UPLOAD_FOLDER, filename))
                file.packet_count = get_capture_count(filename)
                file.date_added = datetime.datetime.now()
                db.session.commit()
            else:
                filetype = splitext(filename)[1].strip('.')
                uuid_filename = '.'.join([str(uuid.uuid4()),filetype])

                new_file = TraceFile(id=str(uuid.uuid4())[:8],
                    name=secure_filename(splitext(filename)[0]),
                    user_id = current_user.id,
                    filename = filename,
                    filetype = filetype,
                    filesize = os.path.getsize(os.path.join(UPLOAD_FOLDER, filename)),
                    packet_count = get_capture_count(filename),
                    date_added = datetime.datetime.now(),
                    status=1
                    )

                db.session.add(new_file)
                db.session.commit()
                db.session.refresh(new_file)

        sniffer.join()

    except Exception as e:
        print(e)
        log('error', 'Exception: %s' % e)
        return render_template('500.html', e=e), 500
    return json.dumps({'status':200, "temp_id":temp_id,"message":[{'type':"success", "message":template_name + " was stopped now."}]})

@app.route('/run_capture', methods=['POST'])
@login_required
def run_capture():
    global sniffer
    temp_id = None
    template = None

    if sniffer is not None:
        template = sniffer.getTemplate()

    try:
        params = json.loads(request.form.to_dict()['data'])
        temp_id = params['temp_id']

        if temp_id is None or temp_id == '':
            return json.dumps({"status":406,"message":[{'type':"warning", "message":"Templte ID was not specified."}]})

        if template is not None:
            if template.id != temp_id:
                return json.dumps({"status":406,"message":[{'type':"warning", "message":"Another process is running. Please stop it and Try again!."}]})

    except Exception as e:
        return json.dumps({"status":406,"message":[{'type':"warning", "message":e}]})

    try:
        template = Template.query.filter_by(id=temp_id).one()

        if template is None:
            return json.dumps({"status":406,"message":[{'type':"danger", "message":template.name + " was not exist!"}]})

        sniffer = PysharkSniffer(current_user.id, db, temp_id, socketio)
        sniffer.start()

    except Exception as e:
        log('error', 'Exception: %s' % e)
        return render_template('500.html', e=e), 500

    return json.dumps({'status':200,"message":[{'type':"success", "message":template.name + " is running now."}]})

@app.route('/livecapture')
@login_required
def livecapture():
   global isRunning
   global curInterfaces
   global bpf_filter

   templates = Template.query.all()

   return render_template('livecaptures.html', templates=templates)

@app.route('/archive')
@login_required
def archive():
    templates = Template.query.all()
    deletedFiles = TraceFile.query.filter_by(status=0).all()

    return render_template('archive.html', deletedFiles=deletedFiles, templates=templates)

@app.route('/savetags/<file_id>', methods=['POST'])

@app.route('/api/v1/<token>/delete/<file_id>')
def api_delete_file(token, file_id):

    try:
        traceFile = TraceFile.query.filter_by(id=file_id).one()
    except NoResultFound:
        return json.dumps({"status":404,"message":"Capture not found.", "id": file_id}), 404

    try:
        user = User.query.filter_by(id=traceFile.user_id).one()
    except NoResultFound:
        return json.dumps({"status":404,"message":"Capture not found.", "id": file_id}), 404


    if current_user.role == 'admin':
        Tag.query.filter_by(file_id=file_id).delete()
        #TraceFile.query.filter_by(id=file_id).delete()
        traceFile.status = 0
        traceFile.date_deleted = datetime.datetime.now()

        db.session.commit()

        # try:
        os.remove(os.path.join(UPLOAD_FOLDER, traceFile.filename))
        # except Exception as e:
        #     print e

        log('info','File deleted by \'%s\': %s.' % (user.username, traceFile.name))
        return json.dumps({"status":200,"message":"Capture deleted successfully.","id":traceFile.id}), 200
    else:

        return json.dumps({"status":403,"message":"Not Authorized."}), 403

@app.route('/captures/delete/<file_id>')
@login_required
def delete_file(file_id):

    api_delete_file(current_user.token, file_id)
    
    return redirect(url_for('home'))

@app.route('/savetags/<file_id>', methods=['POST'])
@login_required
def save_tags(file_id):

    tags = request.data

    #delete tags
    Tag.query.filter_by(file_id=file_id).delete()
    #add remaining tags
    for tag in [x.strip() for x in tags.split(',')]:
        if tag != '':
            new_tag = Tag(name=secure_filename(tag), file_id=file_id)
            db.session.add(new_tag)

    db.session.commit()
    
    return 'Tags have been updated.'

@app.route('/savename/<file_id>', methods=['POST'])
@login_required
def save_name(file_id):

    name = request.data

    if name:
        
        traceFile = TraceFile.query.filter_by(id=file_id).one()

        traceFile.name = secure_filename(name)

        db.session.commit()
    
    return 'Name has been updated.'

@app.route('/downloadfile/<file_id>/<attachment_name>')
@login_required
def download_file(file_id, attachment_name):

    traceFile = TraceFile.query.get_or_404(file_id)

    return send_file(os.path.join(UPLOAD_FOLDER, traceFile.filename), attachment_filename=attachment_name)

@app.route('/help/')
@login_required
def help():
    return render_template('help.html')

@app.route('/logs/')
@login_required
def logs():

    level = request.args.get('level')
    limit = request.args.get('limit')

    try:
        limit = int(limit)
    except (ValueError, TypeError):
        limit=50

    if level:
        logs = Log.query.filter_by(level=level.upper()).order_by(desc(Log.timestamp)).limit(limit).all()
    else:
        logs = Log.query.order_by(desc(Log.timestamp)).limit(limit).all()

    return render_template('logs.html', logs=logs, level=level, limit=limit)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    log('error', 'Exception: %s' % e)
    return render_template('500.html', e=e), 500

@app.before_first_request
def schedule_updates():
    log('info', '-------------- App has started --------------')

def make_shell_context():
    return dict(app=app, db=db, User=User, Tag=Tag, TraceFile=TraceFile, Log=Log, init_db=init_db)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)

#Getting templates
#templates = Template.query.all()

if __name__ == '__main__':
    # app.run(host='0.0.0.0', debug=True, threaded=True)
    #interfaces = get_tshark_interfaces_list()
    #sniffer.start()
    socketio.run(app, host="0.0.0.0", debug=True)
    #manager.run()
