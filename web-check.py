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

def get_text(html):
    """
    Input html bytes.  Returns utf-8 markdown without links

    requests.get().text will be used as the input data
    html2text will be used to remove most of the changing parts of the response
    links will be ignored since most large sites have dynamic links
    if you want to closely monitor a basic site it is probably better to hash
    requests.get().content and not bother stripping the html
    """
    h = html2text.HTML2Text()
    h.ignore_links = True
    return h.handle(html)

def get_md5(html):
    """
    Input html bytes. Returns MD5 hash.
    """
    return hashlib.md5(get_text(html).encode('utf-8')).hexdigest()

def check_failed(checks):
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
    def _md5(check, url_content):
        new_md5 = get_md5(url_content.text)
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

        return ''

    def _string(check, url_content):
        string_found = check.string_to_match in get_text(url_content.text)
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

        return ''

    def _diff(check, url_content):
        text = get_text(url_content.text)
        if text != check.current_content:
            logging.info('Content changed for {}'.format(check.url))
            for line in difflib.context_diff(check.current_content.split('\n'),
                            text.split('\n'),
                            fromfile='Old content for {}'.format(check.url),
                            tofile='New content for {}'.format(check.url)):
                print(line)
            check.current_content = text
            session.commit()

        return ''

    # mapping the class to the internal function used to run a check for that
    # class
    function = {
                MD5Checks: _md5,
                StringChecks: _string,
                DiffChecks: _diff
                }

    def checks(checks):
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

                Run.function[check_type](check, url_content)
                check.alert_after = 0
                session.commit()

        return ''

def validate_input(max_down_time, check_frequency, check_timeout):
    """
    Check's integers are given and that check_timeout is positive.

    Negative max_down_time and check_frequency values have no purpose but are
    still a valid input.  The check would run each time the script is called and
    alert if a connection failed, values of 0 will have the same effect.
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
        print('Error: check-timeout {} given, must be greater than 0'.format(
                                                                check_timeout))
        exit(1)

    return (max_down_time, check_frequency, check_timeout)

def add_md5(url, max_down_time, check_frequency, check_timeout):
    """
    Add a database entry for a url to monitor the md5 hash of.  Returns message
    relating to success.
    """
    url_content = requests.get(url, timeout=check_timeout)
    url_content.raise_for_status()
    if url_content.status_code != 200:
        logging.info('{} error from {}'.format(
                                        url_content.status_code,
                                        check.url))

    try:
        current_hash = get_md5(url_content.text)
    except:
        return 'Error: Failed to hash response from {}'.format(url)
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
        return 'Error: An entry for {} is already in database'.format(url)
    else:
        return 'Added MD5 Check for {}'.format(url)

def add_string(url, string, max_down_time, check_frequency,
        check_timeout):
    """
    Add a database entry for a url to monitor for a string.  Returns message
    relating to success.
    """
    url_content = requests.get(url, timeout=check_timeout)
    url_content.raise_for_status()
    string_exists = 0
    if string in get_text(url_content.text):
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
        return 'Error: An entry for {} is already in database'.format(url)
    else:
        if string_exists:
            print('{} is currently present, will alert if this changes'.format(
                                                                    string))
        else:
            print('{} is currently not present, will alert if this changes'
.format(string))

        return 'Added String Check for {}'.format(url)

def add_diff(url, max_down_time, check_frequency, check_timeout):
    """
    Add a database entry for a url to monitor for any text changes.
    Returns message relating to success.
    """
    url_content = requests.get(url, timeout=check_timeout)
    url_content.raise_for_status()
    check = DiffChecks(url=url,
                    current_content=get_text(url_content.text),
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
        return 'Error: An entry for {} is already in database'.format(url)
    else:
        return 'Added Diff Check for {}'.format(url)

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

def delete_check(check_type, url):
    if check_type == 'md5':
        check = session.query(MD5Checks).filter(MD5Checks.url == url)
    elif check_type == 'string':
        check = session.query(StringChecks).filter(StringChecks.url == url)
    elif check_type == 'diff':
        check = session.query(DiffChecks).filter(DiffChecks.url == url)
    else:
        return 'Chose either md5, string or diff check'

    if check.delete():
        session.commit()
        return '{} check for {} removed'.format(check_type, url)

    return 'There is no {} check for {}'.format(check_type, url)

def import_from_file(import_file):
    """
    Add's new database entrys from a file
    """
    return 'This is broken'
    error_message = 'Import failed: {} is not formatted correctly'
    with open(import_file, 'r') as f:
        for line in f:
            line = line.split('#', 1)[0].rstrip()
            if not line:
                continue
            try:
                check_type, data = line.split('|', 1)
            except ValueError:
                return error_message.format(line)

            max_down_time = default_max_down_time
            check_frequency = default_check_frequency
            check_timeout = default_check_timeout
            if check_type == 'md5':
                # There are two accepted line formats:
                # check_type|url|max_down_time|check_frequency|check_timeout
                # and check_type|url
                if '|' in data:
                    try:
                        url, max_down_time, check_frequency, check_timeout\
                        = data.split('|')
                    except ValueError:
                        return error_message.format(line)

                else:
                    url = data

                print(add_md5(url, max_down_time, check_frequency,
                        check_timeout))
            elif check_type == 'string':
                # There are two accepted line formats:
                # check_type|url|string_to_check|max_down_time|check_frequency
                # |check_timeout
                # and check_type|url
                try:
                    string_to_check, data = data.split('|', 1)
                except ValueError:
                    return error_message.format(line)
                if '|' in data:
                    try:
                        url, max_down_time, check_frequency, check_timeout\
                        = data.split('|')
                    except ValueError:
                        return error_message.format(line)

                else:
                    url = data

                print(add_string(url, string_to_check, max_down_time,
                        check_frequency, check_timeout))
            elif check_type == 'diff':
                # There are two accepted line formats:
                # check_type|url|max_down_time|check_frequency|check_timeout
                # and check_type|url
                if '|' in data:
                    try:
                        url, max_down_time, check_frequency, check_timeout\
                        = data.split('|')
                    except ValueError:
                        return error_message.format(line)

                else:
                    url = data

                print(add_diff(url, max_down_time, check_frequency,
                        check_timeout))
            else:
                return error_message.format(line)

    return ''

if __name__ == '__main__':
    default_max_down_time = 86400
    default_check_frequency = 3600
    default_check_timeout = 30
    default_log_location = 'web_check.log'
    default_database_location = 'web_check.db'
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--check', action='store_true',
        help='Run checks against all monitored urls')
    parser.add_argument('-l', '--list', action='store_true',
        help='Maximum number of set string that can occur')
    parser.add_argument('-d', '--delete', nargs=2,
        help='The entry to delete id must be used')
    parser.add_argument('-a', '--add', nargs='+',
        help='The type of check to setup and what url to check against')
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
        Run.checks(checks)
        errors = check_failed(checks)
        if errors:
            exit(1)

    elif args.list:
        list_checks()
    elif args.add:
        max_down_time, check_frequency, check_timeout = validate_input(
                                                        args.max_down_time,
                                                        args.check_frequency,
                                                        args.check_timeout)
        url = ''
        check_specific_error_message = ''
        try:
            if args.add[0] == 'md5':
                check_specific_error_message = 'Failed to add md5 check for'
                if len(args.add) != 2:
                    print('call as -a \'md5\' \'url-to-check\'')
                    exit(1)
                url = args.add[1]
                print(add_md5(url, max_down_time, check_frequency,
                                    check_timeout))

            elif args.add[0] == 'string':
                check_specific_error_message = 'Failed to add string check for'
                if len(args.add) != 3:
                    print('call as -a \'string\' string-to-check \'url-to-check\'')
                    exit(1)
                url = args.add[2]
                string = args.add[1]
                print(add_string(url, string, max_down_time,
                            check_frequency, check_timeout))

            elif args.add[0] == 'diff':
                check_specific_error_message = 'Failed to add diff check for'
                if len(args.add) != 2:
                    print('call as -a \'diff\' \'url-to-check\'')
                    exit(1)
                url = args.add[1]
                print(add_diff(url, max_down_time, check_frequency,
                            check_timeout))

            else:
                print('Choose either md5, string or diff.')
                exit(1)

        except requests.exceptions.ConnectionError:
            logging.error('Connection Error: {} {}'.format(
                                            check_specific_error_message, url))
            print('Connection Error: {} {}'.format(check_specific_error_message,
                                                url))
            exit(1)
        except requests.exceptions.ReadTimeout:
            logging.error('Timeout Error: {} {}'.format(
                                            check_specific_error_message, url))
            print('Timeout Error: {} {}'.format(check_specific_error_message,
                                            url))
            exit(1)
        except requests.exceptions.MissingSchema as e:
            logging.error('{}: {} {}'.format(e, check_specific_error_message,
                                            url))
            print('{}: {} {}'.format(e, check_specific_error_message, url))
            exit(1)
        except requests.exceptions.InvalidSchema as e:
            logging.error('{}: {} {}'.format(e, check_specific_error_message,
                                            url))
            print('{}: {} {}'.format(e, check_specific_error_message, url))
            exit(1)
        except requests.exceptions.HTTPError as e:
            logging.error('{}: {} {}'.format(e, check_specific_error_message,
                                            url))
            print('{}: {} {}'.format(e, check_specific_error_message, url))
            exit(1)

    elif args.delete:
        if len(args.delete) != 2:
            print('call as -d \'check_type\' \'url-to-remove\'')
            exit(1)

        print(delete_check(args.delete[0], args.delete[1]))
    elif args.import_file:
        error = import_from_file(args.import_file)
        if error:
            print(error)
            exit(1)
    else:
        print("""\
Arguments:
  -h/--help\t\tShow the help message and exit
  -c/--check\t\tRun checks against all monitored urls
  -l/--list\t\tList stored checks from the database
  -a/--add\t\tAdds a check to the database:
  \t\t\t\t-a md5 [url]
  \t\t\t\t-a string [string] [url]
  \t\t\t\t-a diff [url]
  -d/--delete\t\tDelete a check:
  \t\t\t\t-d [check_type] [url]
  --max-down-time\t\tNumber of seconds a site can be down for before warning
  --check-frequency\tNumber of seconds to wait between checks
  --check-timeout\t\tNumber of seconds to timeout get requests after
  --database-location\tSpecify a database name and location
  --import-file\t\tSpecify a file to populate the database from
  --log-location\tSpecify a log file name and location\
  """)
