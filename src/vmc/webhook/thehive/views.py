from rest_framework.decorators import api_view
from rest_framework.response import Response

from vmc.webhook.thehive.handlers import handlers_map
from vmc.webhook.models import TheHive4


def build_event_name(obj_type, oper):
    event_name = '{}_{}'.format(obj_type, oper)
    event_name = event_name.replace('_', ' ')
    return ''.join(x for x in event_name.title() if not x.isspace())



@api_view(['POST'])
def thehive_webhook(request):
    if TheHive4.objects.first():
        event = request.data
        obj_type = event.get('objectType', None)
        oper = event.get('operation', None)
        if obj_type and oper:
            event_name = build_event_name(obj_type, oper)
            if event_name in handlers_map:
                handlers_map[event_name](event)
    return Response()
