from flask import Blueprint

admin_bp = Blueprint('admin', __name__)

# Import routes AFTER defining admin_bp to avoid circular imports
from . import users, tickets, settings
