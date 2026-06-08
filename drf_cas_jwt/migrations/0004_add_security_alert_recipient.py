from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('drf_cas_jwt', '0003_add_refresh_token_family_and_audit_log'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SecurityAlertRecipient',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(help_text='Email que receberá os alertas', max_length=254, unique=True)),
                ('is_active', models.BooleanField(default=True, help_text='Desabilitar sem excluir o registro')),
                ('notify_on_reuse', models.BooleanField(
                    default=True,
                    help_text='Alertar quando reuse de refresh token for detectado'
                )),
                ('notify_on_rate_limit', models.BooleanField(
                    default=False,
                    help_text='Alertar quando rate limit for excedido por um usuário'
                )),
                ('notify_on_login', models.BooleanField(
                    default=False,
                    help_text='Alertar a cada login (útil para contas sensíveis)'
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(
                    blank=True,
                    help_text='Usuário Django associado (opcional)',
                    null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='alert_recipient',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'Destinatário de Alertas de Segurança',
                'verbose_name_plural': 'Destinatários de Alertas de Segurança',
            },
        ),
    ]
