from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired()])
    subtitle = StringField("Subtítulo", validators=[DataRequired()])
    img_url = StringField("URL de la imagen", validators=[DataRequired(), URL()])
    body = CKEditorField("Cuerpo", validators=[DataRequired()])
    submit = SubmitField("Enviar")

class RegisterForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    email = StringField('Correo-e', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Enviar')

class LoginForm(FlaskForm):
    email = StringField('Correo-e', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Enviar')

class CommentForm(FlaskForm):
    comment = CKEditorField("Comentario", validators=[DataRequired()])
    submit = SubmitField("Enviar")