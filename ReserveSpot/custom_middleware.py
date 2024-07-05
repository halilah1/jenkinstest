import logging
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)


class SessionSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_ip = request.META.get('REMOTE_ADDR')
            current_user_agent = request.META.get('HTTP_USER_AGENT')

            session_ip = request.session.get('ip')
            session_user_agent = request.session.get('user_agent')
            session_last_activity = request.session.get('last_activity')

            if session_ip and session_ip != current_ip:
                logger.warning(f"IP address mismatch for user {request.user.username}. Possible session hijacking.")
                request.session.flush()
            elif session_user_agent and session_user_agent != current_user_agent:
                logger.warning(f"User agent mismatch for user {request.user.username}. Possible session hijacking.")
                request.session.flush()

            if session_last_activity:
                last_activity = timezone.datetime.strptime(session_last_activity, '%Y-%m-%d %H:%M:%S.%f')
                if (timezone.now() - last_activity).total_seconds() > settings.SESSION_COOKIE_AGE:
                    request.session.flush()
            request.session['last_activity'] = timezone.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            request.session['ip'] = current_ip
            request.session['user_agent'] = current_user_agent

        response = self.get_response(request)
        return response
