from __future__ import unicode_literals

from flask import render_template, request, redirect, flash
from flask_login import current_user
from flask_classy import route

from core.web.frontend.generic import GenericView
from core.user import User
from core.group import Group
from core.web.helpers import get_object_or_404 #requires_role


class GroupView(GenericView):

    klass = Group

    @route('/profile', methods=["GET", "POST"])
    def profile(self):
        if request.args.get("id"):
            gid = request.args.get("id")
            group = get_object_or_404(Group, id=gid)
            if current_user.has_role("admin") or Group.objects(admins__in=[current_user.id], id=gid, enabled=True):
                return render_template(
                    "group/profile.html",
                    group=group,
                )

        flash("Group not specified", "dangeros")
        return redirect(request.referrer)

class GroupAdminView(GenericView):
    klass = Group

    @route('/usertogroup', methods=["GET", "POST"])
    def usertogroup(self):
        gid = request.form.get("gid")
        uid = request.form.get("uid")
        user = get_object_or_404(User, id=uid)
        group = get_object_or_404(Group, id=gid)
        if user and current_user.has_role("admin") or Group.objects(admins__in=[current_user.id], id=gid, enabled=True):
            group.update(add_to_set__members=user.id)
            flash("Added user: {} to group: {}".format(user.username, group.groupname), "success")
        return redirect(request.referrer)

    @route('/delfromgroup', methods=["GET", "POST"])
    def delfromgroup(self):
        gid = request.args.get("gid")
        uid = request.args.get('uid')
        user = get_object_or_404(User, id=uid)
        group = get_object_or_404(Group, id=gid)
        #ToDo reload page
        if group and current_user.has_role("admin") or Group.objects(admins__in=[current_user.id], id=gid, enabled=True):
            group.update(pull__members=user.id)
            flash("User: {} deleted from group: {}".format(user.username, group.groupname), "success")
        return redirect(request.referrer)


    @route('/usertoadmin', methods=["GET", "POST"])
    def usertoadmin(self):
        gid = request.args.get("gid")
        uid = request.args.get("uid")
        user = get_object_or_404(User, id=uid)
        if user and current_user.has_role("admin") or Group.objects(admins__in=[current_user.id], id=gid, enabled=True):
            #ToDo reload page
            group = get_object_or_404(Group, id=gid)
            group.update(add_to_set__admins=user.id)
            flash("Added user: {} to group: {}".format(user.username, group.groupname), "success")
        return redirect(request.referrer)

    @route('/deladmin', methods=["GET", "POST"])
    def deladmin(self):
        gid = request.args.get("gid")
        uid = request.args.get("uid")
        user = get_object_or_404(User, id=uid)
        group = get_object_or_404(Group, id=gid)
        if group and current_user.has_role("admin") or Group.objects(admins__in=[current_user.id], id=gid, enabled=True):
            #ToDo reload page
            group.update(pull__admins=user.id)
            flash("User: {} deleted from admins: {}".format(user.username, group.groupname), "success")
        return redirect(request.referrer)
