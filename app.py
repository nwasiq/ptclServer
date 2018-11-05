# -*- coding: utf-8 -*-

import pickle
import uuid
import time
import os
from logging.config import dictConfig

import werkzeug

from flask import Flask, request, jsonify, session

from flask_restful import Resource, Api, reqparse
from flask_mail import Mail, Message
from flask_redis import FlaskRedis
from flask_session import Session
from flask_socketio import SocketIO, send, emit
from flask_babel import Babel, _, lazy_gettext as _l

#from flask_log_request_id import RequestID, current_request_id
#from flask_sslify import SSLify
#from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)

#jwt = JWT(app, authenticate, identity)

app.config.update(USERS=dict(admin='secret', wasim='whb123', hamza='ham123'),
  LANGUAGES = ['en', 'ur'],
  SESSION_TYPE = 'redis',
  SECRET_KEY = 'if you speak aloud - then indeed, He knows the secret and what is [even] more hidden [20:7]',
  APP = dict(VERSION='1.0.0', NAME='Smartlink Revamp', URL='https://revamp.smartlink.pk:5000', EXPIRY='2019-12-12 23:59:59'),
  SECRET = dict(JANUS='janus', JWT_AUTH='alskdjf98234lkj238askj29834ksaji8u394', HMAC='alskdj2j34lk2j349kdjf234kjd0fj234923j498', APP='revamp123'),
  VERIFY_TYPES = set(['agent', 'landline', 'mobile', 'sms', 'email']),
  #EX_SEC = dict(JANUS=300, OFFER=300, AGENT=3600, CALL=600, OTP=300, NEW=3600*24*90),
  EX_SEC = dict(JANUS=300, OFFER=300, AGENT=3600, CALL=600, OTP=300, NEW=3*30*24*3600),
  PROVISION_URL = 'http://revamp.smartlink.pk:5055/landlines',
  OTP_COUNTER = dict(REFRESH=3, MAX_ATTEMPTS=3),
  OTP_DIGITS = 4,
  MAIL_DEFAULT_SENDER=('Smartlink Revamp', 'revamp@smartlink.pk'),
  OTP_EMAIL = dict(
                  subject='Smartlink Verification Code',
                  reply_to='No Reply <noreply@smartlink.pk>',
              ),
  SMS_FROM = '1218',
  TEXT = dict(
    VERIFY = dict(
      AGENT = 'Please call 1218 and verify your device within EX_SEC_AGENT seconds',
      CALL = 'We will shortly call on LANDLINE_NUMBER, please answer and press 1 to verify your device',
      MOBILE = 'We will shortly call on MOBILE_NUMBER, please answer and press 1 to verify your device',
      SMS_TEXT = 'Smartlink Verification Code\nOTP',
      SMS = 'We have sms an OTP to MOBILE_NUMBER, please enter the digits below',
      EMAIL = 'We have emailed an OTP to EMAIL_ADDRESS, please enter the digits below',
      EMAIL_TEXT='Please enter OTP into your device to verify it.',
      ERROR = dict(
          SMS = 'SMS to MOBILE_NUMBER failed. Please call 1218 to register your device',
          EMAIL = 'EMAIL to EMAIL_ADDRESS failed. Please call 1218 to register your device',
      )
    )
  )
)


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s'
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default',
    }},
    'root': {
        'level': 'WARN',
        'handlers': ['wsgi']
    }
})

#sslify = SSLify(app)
#RequestID(app)
#auth = HTTPBasicAuth()
#Session(app)

api = Api(app)
rdb = FlaskRedis(app, decode_responses=True)
rbb = FlaskRedis(app)
mail = Mail(app)
socketio = SocketIO(app)
babel = Babel(app)

app.debug=True



def update_counter(conn, name, count=1, now=None):
  PRECISION = [1, 5, 60, 300, 3600, 18000, 86400]
  now = now or time.time()
  pipe = conn.pipeline()
  for prec in PRECISION:
     pnow = int(now / prec) * prec
     hash = '%s:%s'%(prec, name)
     pipe.zadd('known:', hash, 0)
     pipe.hincrby('count:' + hash, pnow, count)
  pipe.execute()


class InvalidUsage(Exception):
    code = 321

    def __init__(self, message, code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if code is not None:
            self.code = code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['error'] = self.code
        app.logger.debug(rv)
        return rv

@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.code = error.code
    return response

@app.errorhandler(InvalidUsage)
def handle_error(error):
    response = jsonify(error.to_dict())
    response.code = error.code
    return response

@socketio.on_error(InvalidUsage)
def handle_error(error):
    response = jsonify(error.to_dict())
    response.code = error.code
    return response



@socketio.on('gimme_auth')
def gimme_auth():
    parser.add_argument('Authorization', location='headers', required=True)
    args = parser.parse_args()
    app.logger.info(args)
    info = Revamp.load_token(args['Authorization'])
    app.logger.debug(info)
    s = Revamp.get_token_from_header(args['Authorization'])
    #s = Revamp.get_token_from_header(session)
    app.logger.debug(s)
    a = rbb.get('auth/' + s)
    app.logger.debug(a)
    if not a:
        raise InvalidUsage('not provisioned yet', code=441)
      
    auth = 'auth/' + str(uuid.uuid4())
    rdb.set(auth, pickle.dumps(dict(info)))
    rdb.delete('auth/' + s)
    rdb.delete(s)
    janus_token = Janus.create_signed_token()
    emit(dict(auth=auth, janus_token=janus_token))


class Janus():
  def create_signed_token(secret=app.config['SECRET']['JANUS'], realm='janus', expiry_seconds=app.config['EX_SEC']['JANUS'], plugins=[]):
    import time
    import hmac
    from hashlib import sha1
    import base64
    app.logger.debug(('janus create_signed_token', realm, expiry_seconds, plugins))
    expiry_timestamp = int(time.time()) + expiry_seconds
    string = ','.join([str(expiry_timestamp), realm, ','.join(plugins)])
    hashed = hmac.new(bytes(secret, 'UTF-8'), bytes(string, 'UTF-8'), sha1) 
    b64 = base64.b64encode(hashed.digest()).decode()
    app.logger.debug(b64)
    return string + ':' + b64


class PTCL():
  def get_crm_info(landline):
      dummy = {'0515493812':dict(billing_id='1515463369', mobile_number='03365999625', email_address='nabeel.mahmood@convergence.pk'),
               '0515551212':dict(billing_id='03008508070', email_address='wasim.baig@convergence.pk', mobile_number='03008508070'),
               '04235700393':dict(billing_id='2105839358', email_address='wasim.baig@convergence.pk', mobile_number='03008508070'),
               '0512283715':dict(billing_id='1512283715', email_address='irfan.ali@ptcl.com.pk', mobile_number='03001234567'),
               '0514865344':dict(billing_id='1514865344', email_address='haider.ali2@ptcl.com.pk', mobile_number='03321234567')}
      if landline not in dummy:
          raise InvalidUsage('no info returned from CRM', code=103)
      crm_info = dummy[landline]
      if not crm_info['billing_id']:
          raise InvalidUsage('crm_info has no billing_id', code=106)
      return crm_info

  def get_eligibility(billing_id):
      dummy = {'1515463369':True,
               '03008508070':True,
               '2105839358':False,
               '100001483925':None,
                '1512283715':True,
                '1514865344':True,
              }
      if billing_id not in dummy:
          raise InvalidUsage('no eligibility returned from CRM', code=116)

      if not dummy[billing_id]:
          raise InvalidUsage('not eligible')

  def provision(landline):
    app.logger.debug((landline))
    import requests
    url = app.config['PROVISION_URL'] + '/' + landline
    app.logger.debug(url)
    r = requests.post(url)
    app.logger.debug((r.text))
    return r.json()

class Revamp():

  def __init__(self):
    True

  def validate_device(device):
    app.logger.debug((device))
    if len(device) < 8:
        app.logger.error('validate_device failed')
        raise InvalidUsage('validate_device failed', code=132)
    return device

  def get_digits(string):
    import re
    return ''.join(re.findall(r'\d+', string))

  def get_token_from_header(token):
    try:  
      return token.split(' ')[1]
    except Exception as e:
      raise InvalidUsage('Invalid Bearer header', code=200)

  def validate_uuid(uuid_string, version=4):
    import uuid
    try:
      uuid.UUID(uuid_string, version=version)
    except:
      raise InvalidUsage('Invalid uuid_string', code=143)
    else:
      return uuid_string

  def load_token(token):
    token = Revamp.get_token_from_header(token)
    try:
      info = rbb.get(token)
    except Exception as e:
      app.logger.error(e)
      raise InvalidUsage('failure reading session, please get new offer', code=209)

    if not info:
        raise InvalidUsage('no such session, please get new offer', code=279)

    try:
      return pickle.loads(info)
    except Exception as e:
      raise InvalidUsage('Invalid pickle loads', code=433)


  def validate_landline(landline):
    n = Revamp.get_digits(landline)
    #TODO: put PTCL REGEX here

    if not len(n):
        app.logger.warning(('no digits entered', n))
        raise InvalidUsage('landline must contain digits', code=227)

    if n[:1] != '0':
        app.logger.warning(('landline doesnt begin with 0', n))
        raise InvalidUsage('landline must start with 0', code=231)

    # lets strip any extra 0
    n = '0' + n.lstrip('0')

    if len(n) < 9:
        app.logger.warning(('landline too short', n))
        raise InvalidUsage('landline too short', code=238)

    if len(n) > 11:
        app.logger.warning(('landline too long', n))
        raise InvalidUsage('landline too long', code=242)

    return n

  def validate_billing_id(billing_id):
    n = Revamp.get_digits(billing_id)
    #TODO: put PTCL REGEX here

    if not len(n):
        app.logger.warning(('no digits entered', n))
        raise InvalidUsage('billing_id must contain digits')

    if len(n) < 9:
        raise InvalidUsage('billing_id too short')

    if len(n) > 11:
        raise InvalidUsage('billing_id too long')

    return n

  def validate_device(device):
    if len(device) < 6:
        app.logger.error('validate_device failed')
        raise InvalidUsage('validate_device failed')
    return device

  def check_blacklist(key, member):
    if rdb.sismember(key, member):
      raise InvalidUsage('%s is blacklisted %s' % (member, key))

  def add_plus(n):
    return '+92' + n[1:]


  def mask_phone_number(n):
    cut = int(len(n)/3)
    masked = n[:cut] + str((len(n) - cut*2) * '*') + n[-cut:]
    return masked

  def mask_email_address(email_address):
    app.logger.debug(email_address)
    t = []
    e = email_address.split('@')
    app.logger.debug(e)
    n = e[0]
    cut = int(len(n)/3)
    t.append(n[:cut] + str((len(n) - cut*2) * '*') + n[-cut:])
    n = e[1]
    cut = int(len(n)/3)
    t.append(n[:cut] + str((len(n) - cut*2) * '*') + n[-cut:])
    return '@'.join(t)

  def generate_hmac_sha1(secret, string):
      from hashlib import sha1
      import hmac
      hashed = hmac.new(bytes(secret, 'UTF-8'), bytes(string, 'UTF-8'), sha1)
      return hashed.hexdigest()

  def send_sms(sender, receiver, text):
      import requests
      params = {'username':'acme', 'password':'acme123', 'account':'convergence', 'smsc':'mo_vp_p2p', 'from':sender, 'to':receiver, 'text':text}
      sendsms_url = 'https://smsc.batuni.pk:13013/cgi-bin/sendsms'
      app.logger.debug(('smsbox', sendsms_url, params))
      try:
          note = requests.get(sendsms_url, params=params)
      except Exception as e:
          note = ('Error sending sms', sendsms_url, params, e)
          raise IOError('Error sending sms')
      else:
          note = 'Sent SMS ' + note.text
          return note

  def check_app_secret(secret):
    if secret != app.config['SECRET']['APP']:
      app.logger.warning('uh oh, wrong secret',secret)
      raise InvalidUsage('Invalid secret', code=410)

  def generate_jwt(payload, secret=app.config['SECRET']['JWT_AUTH'], algorithm='HS256'):
    import jwt
    import time
    try:
      payload['iss'] = app.config['APP']['URL']
      payload['iat'] = time.time()
      return jwt.encode(payload, secret, algorithm)
    except Exception as e:
      app.logger.error(e) 
      raise InvalidUsage('JWT generation failed', code=261)

  def get_jwt_payload(jwt, secret=app.config['SECRET']['JWT_AUTH'], algorithm='HS256'):
    import jwt
    try:
      return jwt.decode(payload, secret, algorithm)
    except Exception as e:
      app.logger.error(e) 
      raise InvalidUsage('JWT decode failed', code=274)
  

  def random_with_N_digits(n):
    from random import randint
    '''generate a N digits long random integer number'''
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

  def generate_otp(device):
    key = '/otp/'  + device
    otp = rdb.get(key)

    if otp:
      app.logger.debug(('otp unexpired found', otp))

      # update the expiry if counter allows
      refresh_counter = rdb.incr(key + '/refresh_counter')
      if refresh_counter < app.config['OTP_COUNTER']['REFRESH']:
        rdb.expire(key, app.config['EX_SEC']['OTP'])
      else:
        rdb.delete(key + '/refresh_counter')
        rdb.delete(key)
        otp=None

    if not otp:
        otp = Revamp.random_with_N_digits(app.config['OTP_DIGITS'])
        rdb.set(key, otp, ex=app.config['EX_SEC']['OTP'])
        app.logger.debug(('otp generated', otp))
    return str(otp)


class Log(Resource):
  
  def get(self):
    return jsonify('Allah is One!')

  def post(self, device):
    parser = reqparse.RequestParser()
    parser.add_argument('app_secret', required=True)
    args = parser.parse_args()

    Revamp.check_app_secret(args['app_secret'])
    app.logger.debug(('app_secret passed'))

    log = {**dict(user_data=request.data, **request.environ)}
    app.logger.debug((device, log))
    now = time.time()
    rdb.zadd('/log', now, log)
    rdb.zadd('/log/' + landline, now, log)
    rdb.zadd('/log/%s/%s' % (landline, device) , now, log)
    return jsonify('Thanks!')
  

class Blacklists(Resource):
  def get(self, key, member):
    return rdb.sismember(key, member)

  def post(self, key, member):
    return db.sadd(key, member)

  def delete(self, key, member):
    return rdb.srem(key, member)

class Contacts(Resource):

    def get(self, device, contact=None):
    
        key = '/devices/%s/contacts' % device
        if contact:
            return str(rdb.sismember(key, contact))
        else:
            contacts = []
            for r in rdb.smembers(key):
                contacts.append(r)
            return contacts

    def post(self, device, contact):
        contacts = '/devices/%s/contacts' % device
        return rdb.sadd(contacts, contact)

    def delete(self, device, contact):
        contacts = '/devices/%s/contacts' % device
        return rdb.srem(contacts, contact)

class Matches(Resource):
  #returns all matching contacts
  def get(self, device):
    l = []
    key = '/devices/%s/contacts' % device
    matches = []
    for r in rdb.sinter(key, '/landlines'):
        matches.append(r)
    return matches

class Messages(Resource):
  def get(self, device):
    l = []
    messages = 'message'

@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(app.config['LANGUAGES'])
      
@app.route('/')
def index():
    import time
    now = time.time()
    t = 'test'
    t=['del', rdb.delete(t), 'sadd', rdb.sadd(t, now), 'smembers', list(rdb.smembers(t)), 'del', rdb.delete(t)]
    e='This text is in your language'
    u=_(e)
    a='Your language is %s' % get_locale()
    app.logger.debug((e, u, a))
    return jsonify(t, e, u, a)

class Auth(Resource):

  def get(self, device):
    # modify this so it takes auth as well as session
    parser = reqparse.RequestParser()
    parser.add_argument('Authorization', location='headers', required=True)
    args = parser.parse_args()
    app.logger.info(args)
    s = Revamp.get_token_from_header(args['Authorization'])
    info = Revamp.load_token(args['Authorization'])
    app.logger.debug((s, info))

    if '/sessions/' in s:
      a = rbb.get('/auth/' + s)
      if not a:
        raise InvalidUsage('not provisioned yet', code=441)
      
      app.logger.debug(info)
      try:
        auth = '/auth/' + str(uuid.uuid4())  
        rdb.set(auth, pickle.dumps(dict(info)), app.config['EX_SEC']['NEW'])
        rdb.delete('/auth/' + s)
        rdb.delete(s)
        janus_token = Janus.create_signed_token()
      except Exception as e:
        app.logger.error(e)
        raise InvalidUsage('error creating auth token', code=526)
      return dict(auth=auth, janus_token=janus_token)

    if '/auth/' in s:
      if not info:
        raise InvalidUsage('no info in key?', code=528)
      auth = '/auth/' + str(uuid.uuid4())
      try:
        rdb.delete(rdb.hget('/devices/' + device, 'current_auth'))
        rdb.set(auth, pickle.dumps(dict(info)), app.config['EX_SEC']['NEW'])
        rdb.hset('/devices/' + device, 'current_auth',  auth)
        janus_token = Janus.create_signed_token()
        rdb.delete(s)
     
      except Exception as e:
        app.logger.error(e)
      return dict(auth=auth, janus_token=janus_token)

    raise InvalidUsage('unhandled Bearer', code=539)


class Offer(Resource):
  def get(self, landline, device):
    parser = reqparse.RequestParser()
    parser.add_argument('app_secret', required=True)
    args = parser.parse_args()

    Revamp.check_app_secret(args['app_secret'])
    app.logger.debug(('app_secret passed'))

    Revamp.check_blacklist('/blacklists/landline', landline)
    app.logger.debug(('validate_landline', landline))

    device = Revamp.validate_device(device)
    Revamp.check_blacklist('/blacklists/device', device)
    app.logger.debug(('validate_device', device))

    crm_info = PTCL.get_crm_info(landline) 
    billing_id = Revamp.validate_billing_id(crm_info['billing_id'])
    Revamp.check_blacklist('/blacklists/billing_id', billing_id)
    app.logger.debug(('validate_billing_id', billing_id))

    PTCL.get_eligibility(billing_id)
    app.logger.debug(('get_eligibility', billing_id))

    offer = []
    if 'agent' in app.config['VERIFY_TYPES']:
      offer.append('agent')
    if 'landline' in app.config['VERIFY_TYPES']:
      offer.append('landline')
    if 'mobile_number' in crm_info and 'mobile' in app.config['VERIFY_TYPES']:
        offer.append('mobile')
    if 'mobile_number' in crm_info and 'sms' in app.config['VERIFY_TYPES']:
        offer.append('sms')
    if 'email' in app.config['VERIFY_TYPES'] and 'email_address' in crm_info:
        offer.append('email')
    app.logger.info(('offer', device, landline, offer, crm_info))

    session = '/sessions/' + str(uuid.uuid4())
    rdb.set(session, pickle.dumps(dict(session=session, device=device, landline=landline, offer=set(offer), crm_info=crm_info)), ex=app.config['EX_SEC']['OFFER'])
    return jsonify(dict(offer=offer, session=session))

  def post(self, landline, device):
    app.logger.debug((device, request.args, request.headers))
    parser = reqparse.RequestParser()
    parser.add_argument('Authorization', location='headers', required=True)
    parser.add_argument('verify_type', required=True)
    args = parser.parse_args()
    app.logger.debug((args))

    device = Revamp.validate_device(device)
    Revamp.check_blacklist('/blacklists/device', device)
    app.logger.debug(('validate_device', device))

    session = Revamp.load_token(args['Authorization'])
    app.logger.debug(('validate_session_id', session))

    app.logger.debug((set([args['verify_type']]), app.config['VERIFY_TYPES'], session['offer']))
    verify_type = set.intersection(set([args['verify_type']]), app.config['VERIFY_TYPES'], session['offer'])
    landline = session['landline']
    crm_info = session['crm_info']
    otp = None # remove this its only for testing

    app.logger.debug(('got session', verify_type, landline, crm_info, otp))

    if 'agent' in verify_type:
      ex=app.config['EX_SEC']['AGENT']
      text = app.config['TEXT']['VERIFY']['AGENT'].replace('EX_SEC_AGENT', app.config['EX_SEC']['VERIFY_AGENT'])

    elif 'landline' in verify_type:
      ex=app.config['EX_SEC']['CALL']
      text = (app.config['TEXT']['VERIFY']['CALL']).replace('LANDLINE_NUMBER', Revamp.mask_phone_number(landline))
      #TODO: queuecall here

    elif 'mobile' in verify_type:
      if not crm_info['mobile_number']: 
        raise InvalidUsage(app.config['TEXT']['VERIFY']['ERROR']['CALL'], code=417)

      ex=app.config['EX_SEC']['CALL']
      text = (app.config['TEXT']['VERIFY']['MOBILE']).replace('MOBILE_NUMBER', Revamp.mask_phone_number(crm_info['mobile_number']))
      #TODO: queuecall here

    elif 'sms' in verify_type:
      if not crm_info['mobile_number']: 
        raise InvalidUsage(app.config['TEXT']['VERIFY']['ERROR']['CALL'], code=429)

      try:
        otp = Revamp.generate_otp(device)
        text = app.config['TEXT']['VERIFY']['SMS_TEXT'].replace('OTP', otp)
        text = Revamp.send_sms(app.config['SMS_FROM'], Revamp.add_plus(crm_info['mobile_number']), text)
      except Exception as e:
        app.logger.error(e)
        #raise InvalidUsage(e, code=437)

      if not text.startswith('Sent SMS 0'):
          app.logger.error(('error sending sms', text))
          #raise InvalidUsage(app.config['TEXT']['VERIFY']['ERROR']['SMS'].replace('MOBILE_NUMBER', Revamp.mask_phone_number(crm_info['mobile_number'])), code=446)

      ex=app.config['EX_SEC']['OTP']
      text = (app.config['TEXT']['VERIFY']['SMS']).replace('MOBILE_NUMBER', Revamp.mask_phone_number(crm_info['mobile_number']))

    elif 'email' in verify_type:
      if not crm_info['email_address']:
        app.logger.error(('No email_address in crm_info', crm_info))
        raise InvalidUsage(app.config['TEXT']['VERIFY']['ERROR']['EMAIL'], code=452)

      email_address = crm_info['email_address']
      try:
        otp = Revamp.generate_otp(device)
        msg = app.config['TEXT']['VERIFY']['EMAIL_TEXT'].replace('EMAIL_ADDRESS', Revamp.mask_email_address(email_address))
        app.logger.debug(msg)
        #mail.send(Message(msg), recipients=[email_address], subject=app.config['OTP_EMAIL']['subject'], reply_to=app.config['OTP_EMAIL']['reply_to'])
      except Exception as e:
        app.logger.error(('Error sending mail', e))
        raise InvalidUsage(app.config['TEXT']['VERIFY']['ERROR']['EMAIL'], code=461)

      ex=app.config['EX_SEC']['OTP']
      text = (app.config['TEXT']['VERIFY']['EMAIL']).replace('EMAIL_ADDRESS', Revamp.mask_email_address(email_address))

    else:
      app.logger.error(('unknown verification type', verify_type))
      raise InvalidUsage('unknown verification type')

    rdb.set('/verifications/' + device, pickle.dumps(session), ex=ex)
    rdb.sadd('/verifications/' + landline, device)
    #TODO: remove otp.otp from below, its only for testing
    return dict(otp=otp, text=text)


class Verify(Resource):

  def post(self, device):

    #TODO: we need to bypass these in case of request from CRM/Agent
    parser = reqparse.RequestParser()
    parser.add_argument('Authorization', location='headers', required=True)
    parser.add_argument('verify_type', required=True)
    args = parser.parse_args()

    if args['verify_type'] not in app.config['VERIFY_TYPES']:
      raise InvalidUsage('%s verification is not enabled' % args['verify_type'])

    session_id = Revamp.get_token_from_header(args['Authorization'])
    session = Revamp.load_token(args['Authorization'])
    app.logger.debug(('validate_session_id', session))
    app.logger.info(session)

    device = Revamp.validate_device(device)
    Revamp.check_blacklist('/blacklists/device', device)
    app.logger.debug(('validate_device', device)) 

    if device != session['device']:
      raise InvalidUsage('session device doesnot match device, register again', code=566)

    if not rdb.exists('/verifications/' + device): 
      raise InvalidUsage('no pending verifications, please request verification from device', code=575)

    verify_info = pickle.loads(rbb.get('/verifications/' + device))
    if device != verify_info['device']:
      raise InvalidUsage('verify_info device doesnot match device, register again', code=566)

    landline = verify_info['landline']
    Revamp.check_blacklist('/blacklists/landline', landline)
    app.logger.debug(('validate_landline', landline))

    verify_type = set.intersection(set([args['verify_type']]), verify_info['offer'])
    app.logger.debug(('verfy_type', verify_type, set([args['verify_type']]), verify_info['offer']))

    if 'landline' in verify_type or 'mobile' in verify_type: 
      raise InvalidUsage('call verification not coded yet', code=581)

    elif 'sms' in verify_type or 'email' in verify_type:
      parser.add_argument('otp', required=True)
      args = parser.parse_args()
      otp = '/otp/' + device
      otp_counter = rdb.incr('/otp/' + device + '/counter')
      rdb.expire('/otp/' + device + '/counter', app.config['EX_SEC']['OTP'])

      if otp_counter > app.config['OTP_COUNTER']['MAX_ATTEMPTS']:
        rdb.delete(otp)
        rdb.delete('/otp/' + device)
        rdb.delete('/otp/' + device + 'refresh_counter')
        rdb.delete('/verifications/' + device)
        rdb.srem('/verifications/' + landline, device)
        raise InvalidUsage('otp expired', code=525)

      if args['otp'] != rdb.get(otp):
        app.logger.debug((args['otp'], '!=', rdb.get(otp)))
        raise InvalidUsage('otp wrong', code=529)

      rdb.delete(otp)
      rdb.delete('/otp/' + device + '/counter')
      rdb.delete('/otp/' + device + '/refresh_counter')

    else:
      raise InvalidUsage('unknown verify_type', code=556)

    now = int(time.time())
    expire_keys = []
    c = '/devices/' + device + '/contacts'
    rdb.sadd(c, landline)
    crm_info = verify_info['crm_info']
    if 'mobile_number' in crm_info:
      rdb.sadd(c, crm_info['mobile_number'])
    # set device to landline
    d = '/devices/' + device
    rdb.hsetnx(d, 'landline', landline)
    rdb.hsetnx(d, 'created_on', now)
    # add device to landline devices
    rdb.zadd('/landlines/' + landline + '/devices', now, device)
    # add device to devices
    rdb.sadd('/devices', device)
    # create auth token
    session = '/auth/' + session_id
    payload = dict(device=device, landline=landline)
    ex = now + app.config['EX_SEC']['OFFER']
    rdb.set(session, pickle.dumps(payload), ex=ex)
    # delete the verifications, not needed any more
    rdb.delete('/verifications/' + device)
    rdb.srem('/verifications/' + landline, device)
    # provision the landline as well, this should be through a queue
    r = PTCL.provision(landline)
    app.logger.debug(r)
    return dict(success=True, session=session)


class Profile(Resource):
  def get(self, device):
    d = dict()
    key = '/devices/' + device 
    return rdb.hgetall(key)

  def post(self, device):
    app.logger.debug((device, request.args, request.headers))
    parser = reqparse.RequestParser()
    parser.add_argument('Authorization', location='headers', required=True)
    parser.add_argument('full_name', help='Your full name')
    parser.add_argument('display_picture', type=werkzeug.datastructures.FileStorage, location='files', help='Your display picture')
    args = parser.parse_args()
    app.logger.debug(args)

    auth_info = Revamp.load_token(args['Authorization'])
    app.logger.debug((auth_info))

    if device != auth_info['device']:
      raise InvalidUsage('auth device doesnot match device, register again', code=566)

    device = Revamp.validate_device(device)
    Revamp.check_blacklist('/blacklists/devices', device)
    app.logger.debug(('validate_device', device))
    
    key = '/devices/' + device 
    if args['full_name']:
      rdb.hset(key, 'full_name', args['full_name'])
    if args['display_picture']:
      try:
        path = os.path.join('static', 'profile', 'display_picture', device)
        args['display_picture'].save(path)
      except Exception as e:
        app.logger.error(('error saving display_picture'))
      else:
        rdb.hset(key, 'display_picture', path)
    
    profile = rdb.hgetall(key)
    app.logger.info((profile))
    return str(profile)


api.add_resource(Blacklists, '/blacklists/<string:key>/<string:member>')
api.add_resource(Offer, '/offer/<string:landline>/<string:device>')
api.add_resource(Log, '/log', '/log/<string:device>')
api.add_resource(Verify, '/verify/<string:device>')
api.add_resource(Contacts, '/contacts/<string:device>', '/contacts/<string:device>/<string:contact>' )
api.add_resource(Matches, '/matches/<string:device>')
api.add_resource(Auth, '/auth/<string:device>')
api.add_resource(Profile, '/profile/<string:device>')


if __name__ == "__main__":
  #yypsocketio.run(app, debug=True, host='0.0.0.0', port=80)#, ssl_context=('ssl/cert.pem', 'ssl/key.pem'))
  app.run(debug=True, host='0.0.0.0', port=80)#, ssl_context=('ssl/cert.pem', 'ssl/key.pem'))
