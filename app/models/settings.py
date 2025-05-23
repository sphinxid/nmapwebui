from app import db

class SystemSettings(db.Model):
    """Model for storing system-wide settings"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<SystemSettings {self.key}={self.value}>'
    
    @classmethod
    def get_setting(cls, key, default=None):
        """Get a setting value by key, or return default if not found"""
        setting = cls.query.filter_by(key=key).first()
        return setting.value if setting else default
    
    @classmethod
    def set_setting(cls, key, value, description=None):
        """Set a setting value, creating it if it doesn't exist"""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            setting.value = str(value)
            if description:
                setting.description = description
        else:
            setting = cls(key=key, value=str(value), description=description)
            db.session.add(setting)
        db.session.commit()
        return setting
    
    @classmethod
    def get_int(cls, key, default=0):
        """Get a setting as an integer"""
        value = cls.get_setting(key, default)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    @classmethod
    def get_bool(cls, key, default=False):
        """Get a setting as a boolean"""
        value = cls.get_setting(key, default)
        if isinstance(value, str):
            return value.lower() in ('true', 'yes', '1', 'on')
        return bool(value)
