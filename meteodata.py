''' Meteorological data gathering tool for mapping applications
    All credits to AEMET (Agencia Estatal de Meteorología), Spain for
    providing access to their observation data

    Ignacio Martinez
    igmartin@movistar.es

    September, 2024
'''

import sys
import os
import time
import json
import fcntl
import requests
import argparse

from util.daemonize import create_pidfile, delpidfile
from util.custlogging import get_logger, DEBUG, INFO, WARNING, ERROR, CRITICAL

logger = get_logger(__name__, INFO)

################################
#
USER_DIR  = "/Users/igmartin"
AEMET_DIR = USER_DIR  + "/aemet"
DATA_DIR  = AEMET_DIR + "/data"

AEMET_KEY_FILE = AEMET_DIR + "/aemet-opendata.apikey"
METEO_BASE     = DATA_DIR  + "/meteodata.dat"
PIDFILE        = DATA_DIR  + "/meteodata.pid"

REQ_OBSV       = (
    "https://opendata.aemet.es/opendata/api/observacion/convencional/todas")
REQ_VALS       = (
    "https://opendata.aemet.es/opendata/api/valores/climatologicos/diarios"
    "/datos/fechaini/%s/fechafin/%s/todasestaciones")

# Observation data record fields and time format
OBSV_F_ID   = 'idema'
OBSV_F_DATE = 'fint'
OBSV_F_PREC = 'prec'
OBSV_F_INSO = 'inso'

OBSV_TIMEFMT = "%Y-%m-%dT%H:%M:%S%z"

# Climatic values record fields
VALS_F_ID   = 'indicativo'
VALS_F_DATE = 'fecha'
VALS_F_PREC = 'prec'
VALS_F_INSO = 'sol'

VALS_TIMEFMT = "%Y-%m-%d"
VALS_WEBFMT  = "%Y-%m-%dT%H:%M:%SUTC"

# Meteobase file record fields
MB_F_STID     = 'id'
MB_F_LASTUPD  = 'lupd'
MB_F_MASKPREC = 'm_prec'
MB_F_MASKINSO = 'm_inso'
MB_F_PREC     = 'prec'
MB_F_INSO     = 'inso'

MB_TIMEFMT = "%Y-%m-%dT%H:%M:%S+0000"

################################
#
# utilty functions used in this module
#
def hour_distance(date1, date2):
    ''' diference in hours between two structured dates '''

    # preserve relative value
    date1_secs = time.mktime(date1)
    date2_secs = time.mktime(date2)

    return (date1_secs - date2_secs)/3600

def num_days(year):
    ''' number of days in a particular year, accounting for leap years '''

    # leap years are all divisible by 4 except those divisible by 100
    # that are not divisible by 400 (e.g. 2100)
    #
    if year % 4 > 0 or (year % 100 == 0 and year % 400 > 0):
        return 365

    return 366

def day_distance(date1, date2):
    ''' difference in days between two structured dates '''

    if date1.tm_year == date2.tm_year:
        return abs(date1.tm_yday - date2.tm_yday)

    date_max = max(date1, date2)
    date_min = min(date1, date2)

    days = num_days(date_min.tm_year) - date_min.tm_yday
    for year in range(date_min.tm_year+1, date_max.tm_year):
        days += num_days(year)
    days += date_max.tm_yday

    return days 

def str_to_float(s):
    ''' translate strings in decimal comma "3,4" format to float numbers '''

    sf = s.replace(",", ".")

    try:
        sf = float(sf)
    except ValueError:
        # This is basically 'Ip' values indicating 'meaningless data'
        sf = 0.0

    return float(sf)
        
def get_aemet_data(url):
    ''' collect meteo data from AEMET's web server '''

    with open(AEMET_KEY_FILE, "r") as f:
        AEMET_KEY = f.read().strip()

    HEADERS  = {"accept": "application/json",
                "api_key": AEMET_KEY}

    DATA_FIELD     = 'datos'
    METADATA_FIELD = 'metadatos'
    STATUS_FIELD   = 'estado'
    DESC_FIELD     = 'descripcion'

    # request observation data
    #
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logger.error("HTTP error: [%d] %s", r.status_code, r.reason)
        return None

    # response include results location and results metadata
    #
    resp = r.json()
    if resp[STATUS_FIELD] != 200:
        logger.error("AEMET error %d: '%s'",
                      resp[STATUS_FIELD], resp[DESC_FIELD])
        sys.exit(1)

    # response is OK
    #
    url = resp[DATA_FIELD]
    r = requests.get(url, headers=HEADERS)
    if r.status_code != 200:
        logger.error("HTTP error: [%d] %s", r.status_code, r.reason)
        return None

    # final result is encoded in Json format. Deserialize
    #
    return r.json()

################################
#
class MeteoData:
    ''' Meteo data file manipulation '''

    def __init__(self, file=METEO_BASE):

        self.file = file
        self.must_create = False

    def read(self):

        try:
            with open(self.file, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                jdata = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except FileNotFoundError:
            self.must_create = True
            jdata = {}

        return jdata

    def write(self, data):

        mode = "w"
        if self.must_create:
            mode = "x"

        try:
            with open(self.file, mode) as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(data, f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except OSError as ose:
            logger.error("error writing to meteo file: '%s'", ose)
            sys.exit(1)

        self.must_create = False

##################
#
EPOCH_TIME = "1970-01-01T01:00:00+0000"

FMASK = 0xFFFFFFFFFFFF
VMASK = 0xFFF800FFF800

class Station:
    ''' a meteorological station abstraction '''

    def __init__(self, id, record):

        self.id     = id
        self.record = record

        # keep reference to mbdata by extending empty record
        if record == {}:
            record |= { MB_F_LASTUPD:  EPOCH_TIME,
                        MB_F_MASKPREC: 0,
                        MB_F_MASKINSO: 0,
                        MB_F_PREC:     [None] * 30,
                        MB_F_INSO:     [None] * 30,
                      }

    def update_mask(self, field, pos):

        self.record[field] |= (1 << pos)

    def mask_isclear(self, field, pos):

        return (self.record[field] & (1 << pos)) == 0

    def get_mask(self, pos):

        mask = (FMASK & (VMASK << (pos % 24))) >> 24

        return mask

    def set_mask(self, field, pos):

        old_mask = self.record[field]
        mask = self.get_mask(pos)
        self.record[field] &= mask 

        return old_mask

    def float_sum(self, col, field, value):

        curval = self.record[field][col]
        if curval is None:
            curval = 0.0

        return round(curval + value, 1)

    def update(self, obsv_record):

        obsv_date = time.strptime(obsv_record[OBSV_F_DATE], OBSV_TIMEFMT)
        obsv_secs = time.mktime(obsv_date)
        scal_date = time.localtime(obsv_secs - 3600)
        scal_dstr = time.strftime(MB_TIMEFMT, scal_date)

        last_update = self.record[MB_F_LASTUPD]
        lupd_date   = time.strptime(last_update, MB_TIMEFMT)

        days = day_distance(scal_date, lupd_date)

        col = 0
        hupd = scal_date.tm_hour

        if scal_date > lupd_date:

            # rotate the day fields
            if 30 > days > 0:
                for _ in range(days):
                    if st.record[OBSV_F_PREC] is not None:
                        st.record[OBSV_F_PREC].pop()
                        st.record[OBSV_F_PREC].insert(0, None)
                    if st.record[OBSV_F_INSO] is not None:
                        st.record[OBSV_F_INSO].pop()
                        st.record[OBSV_F_INSO].insert(0, None)

            # update last date and mask fields
            self.record[MB_F_LASTUPD] = scal_dstr
            self.set_mask(MB_F_MASKPREC, hupd)
            self.set_mask(MB_F_MASKINSO, hupd)
        else:
            col = days

        # update the data fields
        if OBSV_F_PREC in obsv_record:
            if self.mask_isclear(MB_F_MASKPREC, hupd):
                prec = obsv_record[OBSV_F_PREC]
                self.record[MB_F_PREC][col] = (
                      self.float_sum(col, MB_F_PREC, prec))
                self.update_mask(MB_F_MASKPREC, hupd)
            
        if OBSV_F_INSO in obsv_record:
            if self.mask_isclear(MB_F_MASKINSO, hupd):
                inso = float(obsv_record[OBSV_F_INSO]/60)
                self.record[MB_F_INSO][col] = (
                      self.float_sum(col, MB_F_INSO, inso))
                self.update_mask(MB_F_MASKINSO, hupd)
            
    def vals_update(self, vals_record):

        vals_date = time.strptime(vals_record[VALS_F_DATE], VALS_TIMEFMT)

        last_update = self.record[MB_F_LASTUPD]
        lupd_date   = time.strptime(last_update, MB_TIMEFMT)

        days = day_distance(vals_date, lupd_date)

        if 30 > days > 1:
            if VALS_F_PREC in vals_record:
                prec = str_to_float(vals_record[VALS_F_PREC])
                self.record[MB_F_PREC][days] = prec
            if VALS_F_INSO in vals_record:
                inso = str_to_float(vals_record[VALS_F_INSO])
                self.record[MB_F_INSO][days] = inso


if __name__ == '__main__':

    OBSV_MODE = 'obsv'
    VALS_MODE = 'vals'

    DEF_LOGLEVEL = 3
    DEF_MBFILE   = METEO_BASE
    DEF_PIDFILE  = PIDFILE 
    DEF_MODE     = OBSV_MODE

    ############################
    # command line parsing
    #
    argp = argparse.ArgumentParser(description='Meteo data gathering tool')
    argp.add_argument('-V', '--version',  action='version',
          version='meteodata version 1.0')
    argp.add_argument('-l', '--loglevel', type=int,
                            choices=range(1,6),       default=DEF_LOGLEVEL,
          help='log level '
               '(1:debug, 2:info, 3:warning, 4:error, 5:critical) [%d]'
              % DEF_LOGLEVEL)
    argp.add_argument('-p', '--pidfile',              default=DEF_PIDFILE,
          help="pid file")
    argp.add_argument('-b', '--mbfile',               default=DEF_MBFILE,
          help="meteo base data file")
    argp.add_argument('-o', '--obsv-mode', action='store_true', default=True,
          help="meteo observation mode (default)")
    argp.add_argument('-v', '--vals-mode', nargs=2,
          metavar=('date-init', 'date-end'),
          help="meteo values mode, init and end dates in 'yyyy-mm-dd' format")
    opts = argp.parse_args()

    # set log level
    log_levels = (DEBUG, DEBUG, INFO, WARNING, ERROR, CRITICAL)
    logger.setLevel(log_levels[opts.loglevel])

    # check if another process is already running. Then stop if necessary
    if opts.pidfile:
        status = create_pidfile(opts.pidfile)
        if status != 0:
            sys.exit(status)

    # get meteo data from AEMET web site
    if opts.vals_mode:
        try:
            vals_init = time.strptime(opts.vals_mode[0], VALS_TIMEFMT)
            vals_end  = time.strptime(opts.vals_mode[1], VALS_TIMEFMT)
        except ValueError:
            logger.error("Invalid 'yyyy-mm-dd' date format: '%s', '%s'",
                          opts.vals_mode[0], opts.vals_mode[1])
            sys.exit(1)

        # date in AEMET climate values format
        date_init = time.strftime(VALS_WEBFMT, vals_init)
        date_end  = time.strftime(VALS_WEBFMT, vals_end)

        url = REQ_VALS % (date_init, date_end)
    else:
        url = REQ_OBSV

    jobsv = get_aemet_data(url)
    if not jobsv:
        sys.exit(1)

    # Open the meteobase file
    mb = MeteoData(opts.mbfile)
    mbdata = mb.read()

    if opts.vals_mode:
        if mb.must_create:
            logger.error("Meteobase file must exist in values mode")
            sys.exit(1)

        for vals_record in jobsv:
            station_id = vals_record[VALS_F_ID]
            if not station_id in mbdata:
                continue
            st = Station(station_id, mbdata[station_id])

            st.vals_update(vals_record)

    else:
        for obsv_record in jobsv:
            station_id = obsv_record[OBSV_F_ID]
            if station_id not in mbdata:
                 mbdata[station_id] = {}
            st = Station(station_id, mbdata[station_id])
        
            st.update(obsv_record)

    mb.write(mbdata)

