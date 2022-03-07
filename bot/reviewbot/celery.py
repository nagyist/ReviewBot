from __future__ import absolute_import, unicode_literals

import os
import sys

from celery import Celery, VERSION as CELERY_VERSION
from celery.bin.worker import worker
from celery.signals import celeryd_after_setup, celeryd_init
from kombu import Exchange, Queue

from reviewbot import VERSION
from reviewbot.config import config, get_config_file_path, load_config
from reviewbot.repositories import repositories, init_repositories
from reviewbot.tools.base.registry import (get_tool_classes,
                                           load_tool_classes)
from reviewbot.utils.log import get_root_logger


celery = None
logger = get_root_logger()


_manual_url = 'https://www.reviewboard.org/docs/reviewbot/%s.%s/' % VERSION[:2]


class ReviewBotCelery(Celery):
    """A Celery specialization for Review Bot.

    This takes care of initializing Celery with the right options.

    Version Added:
        3.0
    """

    def __init__(self):
        """Initialize Celery."""
        super(ReviewBotCelery, self).__init__(
            main='reviewbot.celery',
            include=['reviewbot.tasks'])


def create_queues():
    """Create the celery queues.

    Returns:
        list of kombu.Queue:
        The queues that this worker will listen to.
    """
    default_exchange = Exchange('celery', type='direct')
    queues = [
        Queue('celery', default_exchange, routing_key='celery'),
    ]

    found_tools = []
    missing_dep_tools = []
    working_dir_tools = []

    # Detect the installed tools and select the corresponding queues to
    # consume from.
    for tool_class in get_tool_classes():
        tool_id = tool_class.tool_id
        tool = tool_class()
        queue_name = '%s.%s' % (tool_id, tool_class.version)

        if tool.check_dependencies():
            found_tools.append(tool_id)

            if tool.working_directory_required:
                # Set up a queue for each configured repository. This way only
                # workers which have the relevant repository configured will
                # pick up applicable tasks.
                working_dir_tools.append(tool_id)

                for repo_name in repositories:
                    repo_queue_name = '%s.%s' % (queue_name, repo_name)

                    queues.append(Queue(
                        repo_queue_name,
                        Exchange(repo_queue_name, type='direct'),
                        routing_key=repo_queue_name))
            else:
                queues.append(Queue(
                    queue_name,
                    Exchange(queue_name, type='direct'),
                    routing_key=queue_name))
        else:
            missing_dep_tools.append(tool_id)

    s = [
        'Welcome!',
        '',
        'Review Bot will connect to %s' % celery.connection().as_uri(),
        '',
    ]

    if found_tools:
        s += [
            'The following tools are available:',
            '',
        ] + [
            '  * %s' % _tool_id
            for _tool_id in found_tools
        ] + ['']

    if missing_dep_tools:
        s += [
            'The following tools are missing dependencies:',
            '',
        ] + [
            '  * %s' % _tool_id
            for _tool_id in missing_dep_tools
        ] + [
            '',
            'See %stools/ for help on installing tools.'
            % _manual_url,
            '',
        ]

    if working_dir_tools:
        if not repositories:
            s += [
                'The following tools cannot be used without one or more '
                'configured repositories in %s:'
                % get_config_file_path(),
                '',
            ] + [
                '  * %s' % _tool_id
                for _tool_id in working_dir_tools
            ]
        else:
            s += [
                'The following tools require a configured repository in %s:'
                % get_config_file_path(),
                '',
            ] + [
                '  * %s' % _tool_id
                for _tool_id in working_dir_tools
            ]

            s += [
                '',
                'Configured repositories include:',
                '',
            ] + [
                '  * %s' % _repository
                for _repository in repositories
            ]

        s += [
            '',
            'See %sconfiguration/#worker-configuration-repositories for '
            'help on configuring repositories.'
            % _manual_url,
            '',
        ]

    logger.info('\n'.join(s))

    return queues


def setup_cookies():
    """Set up cookie storage for API communication.

    This will ensure that the cookie directory exists and that the cookie
    file can be written to.

    Raises:
        IOError:
            The cookie directories could not be created or there's a
            permission error with cookie storage. The specific error will
            be in the exception message.
    """
    cookie_dir = config['cookie_dir']
    cookie_path = config['cookie_path']

    logger.debug('Checking cookie storage at %s', cookie_path)

    # Create the cookie storage directory, if it doesn't exist.
    if not os.path.exists(cookie_dir):
        try:
            os.makedirs(cookie_dir, 0o755)
        except OSError as e:
            raise IOError('Unable to create cookies directory "%s": %s'
                          % (cookie_dir, e))

    can_write_cookies = True

    if os.path.exists(cookie_path):
        # See if we have write access to the file.
        can_write_cookies = os.access(cookie_path, os.W_OK)
    else:
        # Try writing to the file. We'll append, just in case there's another
        # process that managed to write just before this (super unlikely).
        try:
            with open(cookie_path, 'a'):
                pass

            os.chmod(cookie_path, 0o600)
        except (IOError, OSError):
            can_write_cookies = False

    if not can_write_cookies:
        raise IOError('Unable to write to cookie file "%s". Please make '
                      'sure Review Bot has the proper permissions.'
                      % cookie_path)

    logger.debug('Cookies can be stored at %s', cookie_path)


@celeryd_init.connect
def setup_logging(instance, conf, **kwargs):
    """Set up logging for Celery and Review Bot.

    This will configure the log formats we want Celery to use. This differs
    from Celery's defaults not just in the structure of the log entries, but
    also in the addition of the logger name (used to identify different
    tools).

    Args:
        instance (celery.app.base.Celery):
            The Celery instance.

        conf (celery.app.utils.Settings):
            The Celery configuration.

        **kwargs (dict, unused):
            Additional keyword arguments passed to the signal.
    """
    log_format = (
        '%(asctime)s - [%(levelname)s] %(name)s: %(message)s'
    )

    task_log_format = (
        '%(asctime)s - %(processName)s: %(task_name)s(%(task_id)s) - '
        '[%(levelname)s] %(name)s: %(message)s'
    )

    if CELERY_VERSION >= (4, 0):
        conf.update({
            'worker_log_format': log_format,
            'worker_task_log_format': task_log_format,
        })
    else:
        conf.update({
            'CELERYD_LOG_FORMAT': log_format,
            'CELERYD_TASK_LOG_FORMAT': task_log_format,
        })


@celeryd_after_setup.connect
def setup_reviewbot(instance, conf, **kwargs):
    """Set up Review Bot and Celery.

    This will load the Review Bot configuration, store any repository state,
    and set up the queues for the enabled tools.

    Args:
        instance (celery.app.base.Celery):
            The Celery instance.

        conf (celery.app.utils.Settings):
            The Celery configuration.

        **kwargs (dict, unused):
            Additional keyword arguments passed to the signal.
    """
    load_config()

    try:
        setup_cookies()
    except IOError as e:
        logger.error(e)
        sys.exit(1)

    load_tool_classes()
    init_repositories()

    if CELERY_VERSION >= (4, 0):
        conf.accept_content = ['json']
    else:
        conf.CELERY_ACCEPT_CONTENT = ['json']

    instance.app.amqp.queues = create_queues()


def get_celery():
    """Return a Celery instance.

    This will only be constructed the first time this is called. All
    subsequent calls will reuse a cached instance.

    Version Added:
        3.0

    Returns:
        ReviewBotCelery:
        The Celery instance.
    """
    global celery

    if celery is None:
        celery = ReviewBotCelery()

    return celery


def create_worker_command():
    """Create and return the command instance for starting a worker.

    Version Added:
        3.0
    """
    assert celery is not None

    return worker(celery)
