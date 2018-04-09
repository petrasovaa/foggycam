"""FoggyCam captures Nest camera images."""

from urllib.request import urlopen
import urllib
import json
from http.cookiejar import CookieJar
import os
import traceback
import uuid
import threading
import time
import shutil
from datetime import datetime
from subprocess import call


class FoggyCam(object):
    """FoggyCam client class that performs capture operations."""

    nest_username = ''
    nest_password = ''

    nest_user_id = ''
    nest_access_token = ''
    nest_access_token_expiration = ''
    nest_current_user = None

    nest_session_url = 'https://home.nest.com/session'
    nest_user_url = 'https://home.nest.com/api/0.1/user/#USERID#/app_launch'
    nest_api_login_url = 'https://webapi.camera.home.nest.com/api/v1/login.login_nest'
    nest_image_url = 'https://nexusapi-us1.camera.home.nest.com/get_image?uuid=#CAMERAID#&width=#WIDTH#&cachebuster=#CBUSTER#'
    nest_verify_pin_url = 'https://home.nest.com/api/0.1/2fa/verify_pin'

    nest_user_request_payload = {
        "known_bucket_types":["quartz"],
        "known_bucket_versions":[]
    }

    nest_camera_array = []

    is_capturing = False
    cookie_jar = None
    merlin = None
    temp_dir_path = ''
    local_path = ''

    def __init__(self, username, password):
        self.nest_password = password
        self.nest_username = username
        self.cookie_jar = CookieJar()
        self.merlin = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))

        if not os.path.exists('_temp'):
            os.makedirs('_temp')

        self.local_path = os.path.dirname(os.path.abspath(__file__))
        self.temp_dir_path = os.path.join(self.local_path, '_temp')

        self.initialize_session()
        self.login()
        self.initialize_user()

    def initialize_twof_session(self, time_token):
        """Creates the first session to get the access token and cookie, with 2FA enabled."""
        print ("Intializing 2FA session...")

        target_url = self.nest_session_url + "?=_" + time_token
        print (target_url)

        try:
            request = urllib.request.Request(target_url)
            request.add_header('Authorization', 'Basic %s' % self.nest_access_token)

            response = self.merlin.open(request)
            session_data = response.read()

            session_json = json.loads(session_data)

            self.nest_access_token = session_json['access_token']
            self.nest_access_token_expiration = session_json['expires_in']
            self.nest_user_id = session_json['userid']

            print (session_data)
        except urllib.request.HTTPError as err:
            print (err)


    def initialize_session(self):
        """Creates the first session to get the access token and cookie."""

        print ('INFO: Initializing session...')

        payload = {'email':self.nest_username, 'password':self.nest_password}
        binary_data = json.dumps(payload).encode('utf-8')

        request = urllib.request.Request(self.nest_session_url, binary_data)
        request.add_header('Content-Type', 'application/json')

        try:
            response = self.merlin.open(request)
            session_data = response.read()
            session_json = json.loads(session_data)

            self.nest_access_token = session_json['access_token']
            self.nest_access_token_expiration = session_json['expires_in']
            self.nest_user_id = session_json['userid']

            print ('INFO: [PARSED] Captured authentication token:')
            print (self.nest_access_token)

            print ('INFO: [PARSED] Captured expiration date for token:')
            print (self.nest_access_token_expiration)

            cookie_data = dict((cookie.name, cookie.value) for cookie in self.cookie_jar)
            for cookie in cookie_data:
                print (cookie)

            print ('INFO: [COOKIE] Captured authentication token:')
            print (cookie_data["cztoken"])
        except urllib.request.HTTPError as err:
            if err.code == 401:
                error_message = err.read()
                unauth_content = json.loads(error_message)

                if unauth_content["status"].lower() == "verification_pending":
                    print ("Pending 2FA verification!")

                    two_factor_token = unauth_content["2fa_token"]
                    phone_truncated = unauth_content["truncated_phone_number"]

                    print ("Enter PIN you just received on number ending with", phone_truncated)
                    pin = input()

                    payload = {"pin":pin ,"2fa_token":two_factor_token}
                    binary_data = json.dumps(payload).encode('utf-8')

                    request = urllib.request.Request(self.nest_verify_pin_url, binary_data)
                    request.add_header('Content-Type', 'application/json')

                    try:
                        response = self.merlin.open(request)
                        pin_attempt = response.read()

                        parsed_pin_attempt = json.loads(pin_attempt)
                        if parsed_pin_attempt["status"].lower() == "id_match_positive":
                            print ("2FA verification successful.")

                            utc_date = datetime.utcnow()
                            utc_millis_str = str(int(utc_date.timestamp())*1000)
                            
                            print ("Targetting new session with timestamp: ", utc_millis_str)
                            
                            cookie_data = dict((cookie.name, cookie.value) for cookie in self.cookie_jar)

                            print ('INFO: [COOKIE] Captured authentication token:')
                            print (cookie_data["cztoken"])

                            self.nest_access_token = parsed_pin_attempt['access_token']

                            self.initialize_twof_session(utc_millis_str)
                        else:
                            print ("Could not verify. Exiting...")
                            exit()
                    
                    except:
                        traceback.print_exc()

                        print ("Failed 2FA checks. Exiting...")
                        exit()

        print ('INFO: Session initialization complete!')

    def login(self):
        """Performs user login to get the website_2 cookie."""

        print ('INFO: Performing user login...')

        post_data = {'access_token':self.nest_access_token}
        post_data = urllib.parse.urlencode(post_data)
        binary_data = post_data.encode('utf-8')

        print ("INFO: Auth post data")
        print (post_data)

        request = urllib.request.Request(self.nest_api_login_url, data=binary_data)
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')

        response = self.merlin.open(request)
        session_data = response.read()

        print (session_data)

    def initialize_user(self):
        """Gets the assets belonging to Nest user."""

        print ('INFO: Initializing current user...')

        user_url = self.nest_user_url.replace('#USERID#', self.nest_user_id)

        print ('INFO: Requesting user data from:')
        print (user_url)

        binary_data = json.dumps(self.nest_user_request_payload).encode('utf-8')

        request = urllib.request.Request(user_url, binary_data)

        request.add_header('Content-Type', 'application/json')
        request.add_header('Authorization', 'Basic %s' % self.nest_access_token)

        response = self.merlin.open(request)

        response_data = response.read()

        print (response_data)

        user_object = json.loads(response_data)
        for bucket in user_object['updated_buckets']:
            bucket_id = bucket['object_key']
            if bucket_id.startswith('quartz.'):
                camera_id = bucket_id.replace('quartz.', '')
                print ('INFO: Detected camera configuration.')
                print (bucket)
                print ('INFO: Camera UUID:')
                print (camera_id)
                self.nest_camera_array.append(camera_id)

    def capture_images(self, config=None):
        """Starts the multi-threaded image capture process."""

        print ('INFO: Capturing images...')

        self.is_capturing = True

        if not os.path.exists('capture'):
            os.makedirs('capture')

        for camera in self.nest_camera_array:
            camera_path = ''

            # Determine whether the entries should be copied to a custom path
            # or not.
            if not config.path:
                camera_path = os.path.join(self.local_path, 'capture', camera, 'images')
            else:
                camera_path = os.path.join(config.path, 'capture', camera, 'images')

            # Provision the necessary folders for images and videos.
            if not os.path.exists(camera_path):
                os.makedirs(camera_path)

            self.perform_capture(config=config, camera=camera, camera_path=camera_path)
#            image_thread = threading.Thread(target=self.perform_capture, args=(config, camera, camera_path))
#            image_thread.daemon = True
#            image_thread.start()

#        while True:
#            time.sleep(1)

    def perform_capture(self, config=None, camera=None, camera_path=''):
        """Captures images."""

#        while self.is_capturing:
        file_id = str(uuid.uuid4().hex)
        image_name = str(datetime.now())
        image_name = image_name.replace(':', '-').replace(' ', '_')

        image_url = self.nest_image_url.replace('#CAMERAID#', camera).replace('#CBUSTER#', str(file_id)).replace('#WIDTH#', str(config.width))

        request = urllib.request.Request(image_url)
        request.add_header('accept', 'accept:image/webp,image/apng,image/*,*/*;q=0.8')
        request.add_header('accept-encoding', 'gzip, deflate, br')
        request.add_header('user-agent', 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Mobile Safari/537.36')
        request.add_header('referer', 'https://home.nest.com/')

        try:
            response = self.merlin.open(request)

            with open(camera_path + '/' + image_name + '.jpg', 'wb') as image_file:
                image_file.write(response.read())

        except urllib.request.HTTPError as err:
            if err.code == 403:
                self.initialize_session()
                self.login()
                self.initialize_user()
        except Exception:
            print ('ERROR: Could not download image from URL:')
            print (image_url)

            traceback.print_exc()
        finally:
            imgpath = camera_path + '/' + image_name + '.jpg'
            if not os.path.exists(imgpath) or os.path.getsize(imgpath) < 100:
                with open('tmp_email.txt', 'w') as email:
                    email.write("To: " + config.email + '\nFrom: '
                                 + config.email + '\nSubject: NEST alert\n\nImage '
                                 + image_name + ' was not captured\n')
                call('ssmtp ' + config.email + ' < ' + 'tmp_email.txt', shell=True)
                os.remove('tmp_email.txt')
            else:
                try:
                    shutil.copy2(imgpath, config.storage)
                except:
                    with open('tmp_email.txt', 'w') as email:
                        email.write("To: " + config.email + '\nFrom: '
                                     + config.email + '\nSubject: NEST alert\n\nImage '
                                     + image_name + ' was copied to storage\n')
                    call('ssmtp ' + config.email + ' < ' + 'tmp_email.txt', shell=True)
                    os.remove('tmp_email.txt')

