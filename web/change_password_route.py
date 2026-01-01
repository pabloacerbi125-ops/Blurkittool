from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# ===================== CAMBIO DE CONTRASEÑA USUARIO =====================
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not current_user.is_authenticated:
            flash('Debes iniciar sesión.', 'danger')
            return redirect(url_for('login'))
        if not current_password or not new_password or not confirm_password:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('change_password'))
        if not bcrypt.check_password_hash(current_user.password_hash, current_password):
            flash('La contraseña actual es incorrecta.', 'danger')
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash('Las nuevas contraseñas no coinciden.', 'danger')
            return redirect(url_for('change_password'))
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('change_password'))
        current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Contraseña cambiada exitosamente.', 'success')
        return redirect(url_for('menu'))
    return render_template('change_password.html')
