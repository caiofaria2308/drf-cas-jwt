# Migration para adicionar RefreshTokenFamily e TokenAuditLog

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('drf_cas_jwt', '0002_remove_device_and_update_token'),
    ]

    operations = [
        migrations.CreateModel(
            name='RefreshTokenFamily',
            fields=[
                (
                    'id',
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'jti',
                    models.CharField(
                        db_index=True,
                        help_text='JWT ID (jti claim) do refresh token',
                        max_length=255,
                        unique=True,
                    ),
                ),
                (
                    'parent_jti',
                    models.CharField(
                        blank=True,
                        help_text='jti do refresh anterior (se foi rotacionado)',
                        max_length=255,
                        null=True,
                    ),
                ),
                ('ip', models.GenericIPAddressField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'rotated_at',
                    models.DateTimeField(
                        blank=True,
                        help_text='Data quando esse jti foi rotacionado para um novo',
                        null=True,
                    ),
                ),
                (
                    'revoked_at',
                    models.DateTimeField(
                        blank=True,
                        help_text='Data da revogação por reuse ou outro motivo',
                        null=True,
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'indexes': [
                    models.Index(fields=['user', 'revoked_at']),
                    models.Index(fields=['jti', 'revoked_at']),
                ],
            },
        ),
        migrations.CreateModel(
            name='TokenAuditLog',
            fields=[
                (
                    'id',
                    models.UUIDField(
                        default=uuid.uuid4,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    'event',
                    models.CharField(
                        choices=[
                            ('LOGIN', 'Login'),
                            ('LOGOUT', 'Logout'),
                            ('REFRESH', 'Token Refresh'),
                            ('REFRESH_DENIED', 'Refresh Negado'),
                            ('AUTH_DENIED', 'Autenticação Negada'),
                            ('REUSE_DETECTED', 'Reuse de Refresh Detectado'),
                        ],
                        max_length=20,
                    ),
                ),
                (
                    'reason',
                    models.CharField(
                        choices=[
                            ('invalid_token', 'Token Inválido'),
                            ('token_reuse', 'Reuse de Token'),
                            ('rate_limit', 'Rate Limit Excedido'),
                            ('expired', 'Token Expirado'),
                            ('device_mismatch', 'Device Não Corresponde'),
                            ('success', 'Sucesso'),
                        ],
                        default='success',
                        max_length=30,
                    ),
                ),
                ('ip', models.GenericIPAddressField()),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'indexes': [
                    models.Index(fields=['user', 'created_at']),
                    models.Index(fields=['event', 'created_at']),
                ],
            },
        ),
    ]
