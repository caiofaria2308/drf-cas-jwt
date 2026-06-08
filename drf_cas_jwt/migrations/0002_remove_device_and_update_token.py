# Generated migration to remove Device model and simplify Token

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('drf_cas_jwt', '0001_initial'),
    ]

    operations = [
        # Remove the device FK from Token first
        migrations.RemoveField(
            model_name='token',
            name='device',
        ),
        # Delete Device model
        migrations.DeleteModel(
            name='Device',
        ),
        # Increase token field max_length for HMAC-SHA256 (64 chars hex)
        migrations.AlterField(
            model_name='token',
            name='token',
            field=models.CharField(max_length=64, verbose_name='Token JWT (HMAC-SHA256)'),
        ),
        # Add user FK to Token
        migrations.AddField(
            model_name='token',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
        # Add jti field for refresh token tracking
        migrations.AddField(
            model_name='token',
            name='jti',
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text='JWT ID (jti claim) para rastreamento de refresh tokens',
                max_length=255,
                null=True,
                unique=True,
            ),
        ),
        # Update Meta - remove unique_together, add indexes
        migrations.RemoveIndex(
            model_name='token',
            name='token_token_device_idx',
        ),
        migrations.AddIndex(
            model_name='token',
            index=models.Index(fields=['user', 'deleted_at'], name='token_user_deleted_idx'),
        ),
        migrations.AddIndex(
            model_name='token',
            index=models.Index(fields=['jti', 'deleted_at'], name='token_jti_deleted_idx'),
        ),
    ]
