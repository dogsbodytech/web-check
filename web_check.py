#!/usr/bin/env python3
try:
    import sys
    import logging
    import argparse
    import time
    import requests
    import html2text
    import hashlib
    import difflib
    import sqlalchemy
    from sqlalchemy import Column, Integer, String, Table, MetaData
    from sqlalchemy.ext.declarative import declarative_base, declared_attr
    from sqlalchemy.orm import sessionmaker
except ImportError:
    print("""Import failed make sure you have set up the virtual enviroment.
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt""")
    exit(1)

Base = declarative_base()
metadata = MetaData()

class BaseCheck(object):
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True)
    max_down_time = Column(Integer)
    check_frequency = Column(Integer)
    check_timeout = Column(Integer)
    run_after = Column(Integer)
    alert_after = Column(Integer)
    alerted = Column(Integer)

class MD5Checks(Base, BaseCheck):
    current_hash = Column(String)
    old_hash = Column(String)

class StringChecks(Base, BaseCheck):
    string_to_match = Column(String)
    present = Column(Integer)

class DiffChecks(Base, BaseCheck):
    current_content = Column(String)

checks = (MD5Checks, StringChecks, DiffChecks)
default_max_down_time = 86400
default_check_frequency = 3600
default_check_timeout = 30
default_log_location = 'web_check.log'
default_database_location = 'web_check.db'

def get_text(response_object):
    """
    Input requests object.  Returns utf-8 markdown without links

    requests.get() will be used as the input data
    if the response is already text it is simply returned, otherwise
    html2text will be used to remove most of the changing parts of the response
    links will be ignored since most large sites have dynamic links
    if you want to closely monitor a basic site it is probably better to hash
    requests.get().content and not bother stripping the html
    """
    if 'text/plain' in response_object.headers.get('content-type'):
        return response_object.text

    h = html2text.HTML2Text()
    h.ignore_links = True
    return h.handle(response_object.text)

def get_md5(response_object):
    """
    Input html bytes. Returns MD5 hash.
    """
    return hashlib.md5(get_text(response_object).encode('utf-8')).hexdigest()

def check_failed(session, checks):
    error_message = 'Error: {} failed connection to {}\n\
has now exceded the max down time, there will not be another warning until it \
comes back up.'
    errors = 0
    for check_type in checks:
        # There seem to be 3 ways to make the query I want through sqlalchemy
        # http://docs.sqlalchemy.org/en/latest/orm/tutorial.html
        # I've gone with filter multiple times since I like how it looks more
        for check in session.query(check_type).filter(
                check_type.alert_after != 0).filter(
                check_type.alert_after < time.time()).filter(
                check_type.alerted == 0).order_by(check_type.id):
            print(error_message.format(check_type.__name__, check.url))
            logging.warning(error_message.format(check_type.__name__,
                                            check.url))
            errors += 1
            check.alerted = 1
            session.commit()

    return errors

class Run:
    def _md5(session, check, url_content):
        new_md5 = get_md5(url_content)
        if new_md5 != check.current_hash:
            if new_md5 == check.old_hash:
                logging.info('MD5 reverted for {}'.format(check.url))
                print('The md5 for {} has been reverted'.format(check.url))
            else:
                logging.info('MD5 changed for {}'.format(check.url))
                print('The md5 for {} has changed'.format(check.url))

            check.old_hash = check.current_hash
            check.current_hash = new_md5
            session.commit()

    def _string(session, check, url_content):
        string_found = check.string_to_match in get_text(url_content)
        if string_found != check.present:
            if check.present:
                logging.info('{} is no longer present on {}'.format(
                                                        check.string_to_match,
                                                        check.url))
                print('{} is no longer present on {}'.format(
                                                        check.string_to_match,
                                                        check.url))
                check.present = 0
            else:
                logging.info('{} is now present on {}'.format(
                                                        check.string_to_match,
                                                        check.url))
                print('{} is now present on {}'.format(
                                                    check.string_to_match,
                                                    check.url))
                check.present = 1

            session.commit()

    def _diff(session, check, url_content):
        if not 'text/plain' in url_content.headers.get('content-type'):
            text = get_text(url_content)

        if text != check.current_content:
            logging.info('Content changed for {}'.format(check.url))
            for line in difflib.context_diff(check.current_content.split('\n'),
                            text.split('\n'),
                            fromfile='Old content for {}'.format(check.url),
                            tofile='New content for {}'.format(check.url)):
                print(line)
            check.current_content = text
            session.commit()

    # mapping the class to the internal function used to run a check for that
    # class
    function = {
                MD5Checks: _md5,
                StringChecks: _string,
                DiffChecks: _diff
                }

    def all_checks(session, checks):
        for check_type in checks:
            for check in session.query(check_type).filter(check_type.run_after <
                        time.time()).order_by(check_type.id):
                now = time.time()
                check.run_after = now + check.check_frequency
                check.alert_after = now + check.max_down_time
                session.commit()
                try:
                    url_content = requests.get(check.url,
                                        timeout=check.check_timeout)
                except requests.exceptions.ConnectionError:
                    logging.info('Connection Error: when connecting to {}'
                                                            .format(check.url))
                    continue
                except requests.exceptions.ReadTimeout:
                    logging.info('Timeout during connection to {}'.format(
                                                                    check.url))
                    continue

                try:
                    url_content.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    logging.info(e)
                    continue

                if check.alerted:
                    check.alerted = 0
                    session.commit()
                    # This is information but the down is a warning and if I am
                    # logging the down then I want to log the up or it will be
                    # a pain to troubleshoot
                    logging.warning('Reastablished {} connection to {}'.format(
                                            check_type.__name__, check.url))
                    print('Reastablished {} connection to {}'.format(
                                            check_type.__name__, check.url))

                Run.function[check_type](session, check, url_content)
                check.alert_after = 0
                session.commit()

        return ''
class Add:
    def _validate_input(max_down_time, check_frequency, check_timeout):
        """
        Check's integers are given and that check_timeout is positive.

        Negative max_down_time and check_frequency values have no purpose but
        are still a valid input.  The check would run each time the script is
        called and alert if a connection failed, values of 0 will have the same
        effect.
        """
        try:
            max_down_time = int(max_down_time)
        except ValueError:
            print('Error: max_down_time {} given, must be an integer'.format(
                                                                max_down_time))
            exit(1)

        try:
            check_frequency = int(check_frequency)
        except ValueError:
            print('Error: check_frequency {} given, must be an integer'.format(
                                                            check_frequency))
            exit(1)

        try:
            check_timeout = int(check_timeout)
        except ValueError:
            print('Error: check_timeout {} given, must be an integer'.format(
                                                                check_timeout))
            exit(1)

        if not check_timeout > 0:
            print('Error: check-timeout {} given, must be greater than 0'
                                                        .format(check_timeout))
            exit(1)

        return (max_down_time, check_frequency, check_timeout)

    def check(session,
            check_type,
            url,
            max_down_time,
            check_frequency,
            check_timeout,
            string=None):
        max_down_time, check_frequency, check_timeout = Add._validate_input(
                                                        max_down_time,
                                                        check_frequency,
                                                        check_timeout)
        try:
            url_content = requests.get(url, timeout=check_timeout)
        except requests.exceptions.ConnectionError:
            logging.error('Connection Error: failed to add {} check for {}'
                                                .format(check_type, url))
            print('Connection Error: {} {}'.format(check_type, url))
            exit(1)
        except requests.exceptions.ReadTimeout:
            logging.error('Timeout Error: failed to add {} check for {}'.format(
                                                check_type, url))
            print('Timeout Error: failed to add {} check for {}'.format(
                                                check_type, url))
            exit(1)
        except requests.exceptions.MissingSchema as e:
            logging.error('{}: failed to add {} check for {}'.format(e,
                                                check_type, url))
            print('{}: failed to add {} check for {}'.format(e, check_type,
                                                url))
            exit(1)
        except requests.exceptions.InvalidSchema as e:
            logging.error('{}: failed to add {} check for {}'.format(e,
                                                check_type, url))
            print('{}: failed to add {} check for {}'.format(e, check_type,
                                                url))
            exit(1)
        try:
            url_content.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logging.error('{}: failed to add {} check for {}'.format(e,
                                                check_type, url))
            print('{}: failed to add {} check for {}'.format(e, check_type,
                                                url))
            exit(1)

        if check_type == 'md5':
            current_hash = get_md5(url_content)
            check = MD5Checks(url=url,
                        current_hash=current_hash,
                        alert_after=0,
                        alerted=0,
                        max_down_time=max_down_time,
                        run_after=0,
                        check_frequency=check_frequency,
                        check_timeout=check_timeout)
            session.add(check)
            try:
                session.commit()
            except sqlalchemy.exc.IntegrityError:
                session.rollback()
                print('Error: An entry for {} is already in database'.format(
                                                                        url))
                exit(1)
            else:
                print('Added MD5 Check for {}'.format(url))

        elif check_type == 'string':
            if not string:
                print('A string is required')
                exit(1)
            string_exists = 0
            if string in get_text(url_content):
                string_exists = 1

            check = StringChecks(url=url,
                            string_to_match=string,
                            present=string_exists,
                            alert_after=0,
                            alerted=0,
                            max_down_time=max_down_time,
                            run_after= 0,
                            check_frequency=check_frequency,
                            check_timeout=check_timeout)
            session.add(check)
            try:
                session.commit()
            except sqlalchemy.exc.IntegrityError:
                session.rollback()
                print('Error: An entry for {} is already in database'.format(
                                                                        url))
                exit(1)
            else:
                if string_exists:
                    print('{} is currently present, will alert if this changes'
                                                            .format(string))
                else:
                    print('{} is currently not present, will alert if this '\
                            'changes'.format(string))

                print('Added String Check for {}'.format(url))

        elif check_type == 'diff':
            check = DiffChecks(url=url,
                            current_content=get_text(url_content),
                            alert_after=0,
                            alerted=0,
                            max_down_time=max_down_time,
                            run_after=0,
                            check_frequency=check_frequency,
                            check_timeout=check_timeout)
            session.add(check)
            try:
                session.commit()
            except sqlalchemy.exc.IntegrityError:
                session.rollback()
                print('Error: An entry for {} is already in database'.format(
                                                                        url))
                exit(1)
            else:
                print('Added Diff Check for {}'.format(url))

        else:
            print('Please choose a valid check')
            exit(1)

        return ''

    def from_file(session, import_file):
        """
        Add's new database entrys from a file
        """
        def get_kwargs(*args):
            for arg in args:
                print(arg)
            return args
        with open(import_file, 'r') as f:
            for line_number, line in enumerate(f, 1):
                # ignore everything after a #
                line = line.split('#', 1)[0].rstrip()
                if not line:
                    continue

                try:
                    Add.check(session, *line.split('|'))
                except TypeError:
                    logging.warning('Warning: line {} was skipped, it is not '
                        'in an accepted format'.format(line_number))
                    print('Warning: line {} was skipped, it is not in an '\
                        'accepted format'.format(line_number))
                    raise
                except:
                    logging.error('Error: line {} was skipped due to an error'
                                                    .format(line_number))
                    print('Error: line {} was skipped due to an error'
                                                    .format(line_number))
                else:
                    print('Check for line {} was added'.format(line_number))

        return ''

def list_checks():
    """
    List all of the checks from the database in a table like format.
    """
    # I am removing the old list checks since it is horid
    print('use sqlite3 to view the tables')
    print('.tables')
    print('PRAGMA table_info(<table>);')
    print('select * from <table>;')
    return ''

def delete_check(session, check_type, url):
    if check_type == 'md5':
        check = session.query(MD5Checks).filter(MD5Checks.url == url)
    elif check_type == 'string':
        check = session.query(StringChecks).filter(StringChecks.url == url)
    elif check_type == 'diff':
        check = session.query(DiffChecks).filter(DiffChecks.url == url)
    else:
        print('Chose either md5, string or diff check')
        exit(1)

    if check.delete():
        session.commit()
        print('{} check for {} removed'.format(check_type, url))
    else:
        print('There is no {} check for {}'.format(check_type, url))
        exit(1)

    return ''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', nargs='?',
        help='The url to add or remove a check for')
    parser.add_argument('-c', '--check', action='store_true',
        help='Run checks against all monitored urls')
    parser.add_argument('-l', '--list', action='store_true',
        help='Maximum number of set string that can occur')
    parser.add_argument('-d', '--delete',
        help='The check type to be deleted')
    parser.add_argument('-a', '--add',
        help='The type of check to setup')
    parser.add_argument('-s', '--string', default=None,
        help='Additional string used by a check')
    parser.add_argument('--max-down-time', type=int,
        default=default_max_down_time,
        help='Number of seconds a site can be down for before warning')
    parser.add_argument('--check-frequency', type=int,
        default=default_check_frequency,
        help='Specify the number of seconds to check after')
    parser.add_argument('--check-timeout', type=int,
        default=default_check_timeout,
        help='Specify the number of seconds to check_timeout after')
    parser.add_argument('--database-location',
        default=default_database_location,
        help='Specify a database name and location')
    parser.add_argument('--import-file',
        help='Chose a file to populate the database from')
    parser.add_argument('--log-location',
        default=default_log_location,
        help='Specify a log file name and location')
    parser.allow_abbrev = False
    args = parser.parse_args()
    logging.basicConfig(filename=default_log_location, level=logging.WARNING,
                format=('%(levelname)s:%(asctime)s %(message)s'))
    engine = sqlalchemy.create_engine('sqlite:///{}'.format(
                                                    args.database_location))

    try:
        Base.metadata.create_all(engine)
    except sqlalchemy.exc.OperationalError:
        print('Could not create or connect to database at {}'.format(
                                                    args.database_location))
        exit(1)

    Session = sessionmaker(bind=engine)
    session = Session()
    if args.check:
        Run.all_checks(session, checks)
        errors = check_failed(session, checks)
        if errors:
            exit(1)

    elif args.list:
        list_checks()
    elif args.add:
        if not args.url:
            print('A please define a url to add the check for')
            exit(1)

        Add.check(session,
                    args.add,
                    args.url,
                    args.max_down_time,
                    args.check_frequency,
                    args.check_timeout,
                    args.string)
    elif args.delete:
        if not args.url:
            print('A please define a url to delete the check for')
            exit(1)

        delete_check(session, args.delete, args.url)
    elif args.import_file:
        Add.from_file(session, args.import_file)
    else:
        print("""\
Arguments:
  url\t\t\tWhen adding or removing checks specify the url
  -h/--help\t\tShow the help message and exit
  -c/--check\t\tRun checks against all monitored urls
  -l/--list\t\tList stored checks from the database
  -a/--add\t\tSpecify a check type to add a check for
  -s/--string\t\tSpecify a string to be used by a check
  -d/--delete\t\tSpecify a check type to delete a check for
  --max-down-time\tNumber of seconds a site can be down for before warning
  --check-frequency\tNumber of seconds to wait between checks
  --check-timeout\tNumber of seconds to timeout get requests after
  --database-location\tSpecify a database name and location
  --import-file\t\tSpecify a file to populate the database from
  --log-location\tSpecify a log file name and location\
  """)

if __name__ == '__main__':
    main()
