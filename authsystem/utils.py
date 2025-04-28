from django.core.serializers.json import DjangoJSONEncoder

class MongoJSONEncoder(DjangoJSONEncoder):
    def default(self, obj):
        # Handle standard Django IDs
        if hasattr(obj, 'id'):
            return str(obj.id)
        return super().default(obj) 