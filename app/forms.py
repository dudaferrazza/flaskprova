from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt

from app import db
from app.models import Contato, User, Post, PostComentarios
bcrypt = Bcrypt()

class UserForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    sobrenome = StringField('Sobrenome', validators=[DataRequired()])
    email = StringField('E-Mail', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    confirmacao_senha = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('senha')])
    btnSubmit = SubmitField('Cadastrar')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Usuário já cadastrado com esse E-mail!!!')

    def save(self):
        senha_hash = bcrypt.generate_password_hash(self.senha.data).decode('utf-8')
        user = User(
            nome=self.nome.data,
            sobrenome=self.sobrenome.data,
            email=self.email.data,
            senha=senha_hash
        )
        db.session.add(user)
        db.session.commit()
        return user
    
class LoginForm(FlaskForm):
        email = StringField('E-Mail', validators=[DataRequired(),Email()])
        senha = PasswordField('Senha', validators=[DataRequired()])
        btnSubmit = SubmitField('Login')

        def login(self):
            #Recuperar o usuário do e-mail
            user = User.query.filter_by(email=self.email.data).first()
            #Verificar se a senha é válida
            if user:
                if bcrypt.check_password_hash(user.senha, self.senha.data.encode('utf-8')):
                    #Retornar o usuário
                    return user
                else:
                    raise Exception('Senha Incorreta!')
            else:
                raise Exception('Usuário não encontrado!')

class ContatoForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    email = StringField('E-Mail', validators=[DataRequired(),Email()])
    assunto = StringField('Assunto', validators=[DataRequired()])
    mensagem = StringField('Mensagem', validators=[DataRequired()])
    btnSubmit = SubmitField('Enviar')

    def save(self):
        contato = Contato(
            nome = self.nome.data,
            email = self.email.data,
            assunto = self.assunto.data,
            mensagem = self.mensagem.data
        )

class PostForm (FlaskForm):
    mensagem =  StringField('Mensagem', validators=[DataRequired()])
    btnSubmit = SubmitField('Enviar')

    def save(self, user_id):
        post = Post(
            mensagem=self.mensagem.data,
            user_id=user_id
        )

class PostComentarioForm(FlaskForm):
    comentario = StringField('Comentário', validators=[DataRequired()])
    btnSubmit = SubmitField('Enviar')

    def save(self, user_id, post_id):
        comentario = PostComentarios (
            comentario=self.comentario.data,
            user_id=user_id,
            post_id=user_id
        )

        db.session.add(comentario)
        db.session.commit()