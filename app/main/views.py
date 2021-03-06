from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response, session
#from flask_login import login_required, current_user
from flask_sqlalchemy import get_debug_queries
from . import main
from .forms import UrlForm, DeForm, SelForm
from .. import db
from ..models import Serv 
import re
from markupsafe import Markup

#from ..decorators import admin_required, permission_required



@main.route('/', methods=['GET', 'POST'])
def index():
    #session["distinct_servs"] = [serv[0] for serv in db.session.query(Serv.servname).distinct()]
    servs = Serv.query.all()
    return render_template('index.html', servs=servs)

@main.route("/server", methods=['GET', 'POST'])
def ip_index():
    #session["distinct_ips"] = [ip[0] for ip in db.session.query(Serv.ip).distinct()]
    servs = Serv.query.order_by("ip").all()
    return render_template('server.html', servs=servs)

@main.route("/deploy", methods=['GET', 'POST'])
def deploy_index():
    serv_info = {} 
    distinct_servs = [serv[0] for serv in db.session.query(Serv.servname).distinct()]
    distinct_ips = [ip[0] for ip in db.session.query(Serv.ip).distinct()]
    return render_template('deploy.html', serv_info=serv_info, distinct_servs=distinct_servs, distinct_ips=distinct_ips)

@main.route("/deploy/<servname>", methods=['GET', 'POST'])
def deploy(servname):
    distinct_servs = [serv[0] for serv in db.session.query(Serv.servname).distinct()]
    distinct_ips = [ip[0] for ip in db.session.query(Serv.ip).distinct()]
    serv_info = {}
    serv_info["servname"] = servname
    serv_ips = []
    servs = Serv.query.filter_by(servname=servname).all()
    for serv in servs:
        serv_ips.append(serv.ip)
        serv_info["consulname"] = serv.consulname
    serv_info["servip"] = serv_ips
    if request.method == 'POST':
        session["ips"] = request.values.getlist("ips")
        if not session["ips"]:
            flash(Markup('No ips selected!'), 'warning')
            return redirect(url_for('main.deploy', servname=servname))
        session["servname"] = servname
        session["consulname"] = serv.consulname
        action = request.values.get("deploy")
        if action == "auto_deploy":
            return redirect(url_for('main.update'))
        else:
            return "manual"

    return render_template('deploy.html', serv_info=serv_info, distinct_servs=distinct_servs, distinct_ips=distinct_ips)

@main.route("/update", methods=['GET', 'POST'])
def update():
    serv_info = {}
    serv_info["servname"] = session["servname"]
    serv_info["servips"] = session["ips"]
    serv_info["consulname"] = session["consulname"]
    form = UrlForm()
    if form.validate_on_submit():
        match_re = re.compile("(http://)?(\w+)/([^/:]+)-([\d+.]+).(jar|zip)")
        jar_name_re = re.search(match_re,form.name.data)
        if jar_name_re and jar_name_re.group(3) == serv_info["servname"]:
            flash(Markup('deploy successfully!'), 'success')
        else:
            flash(Markup('please check your URL!'), 'success')
            #flash('please check your URL!', 'warning')
            return redirect(url_for('main.update'))

    return render_template('update.html', form=form, serv_info=serv_info)


