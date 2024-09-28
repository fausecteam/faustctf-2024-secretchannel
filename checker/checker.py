#!/usr/bin/env python3

from ctf_gameserver import checkerlib

import requests
import utils
import logging
from bs4 import BeautifulSoup
import secrets
import re


class NotFound(Exception):
    """Custom exception class for specific error handling."""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

def find_token(msg):
    r = re.findall("<p class=\"big\">([^<]*)</p>", msg)
    if r == None or len(r) != 2:
        raise NotFound('Could not find')
    token, id = re.findall("<p class=\"big\">([^<]*)</p>", msg)
    return id, token


def find_message(msg):
    # print(msg)
    r = re.search("<h1>Secret Message</h1><p>([^<]*)</p>", msg)
    if r == None:
        raise NotFound('Did not find da massage')
    return r.group(1)



class TemplateChecker(checkerlib.BaseChecker):
    #fd66:666:995::2
    @property
    def base_url(self):
        return f'http://[{self.ip}]:3000'

    # Create a new token
    def create(self, content, pw):
        logging.info(f"Creating token with content {content} and password {pw}")
        return find_token(requests.post(f'{self.base_url}/create', data={'type': 'text', 'content': content, 'pw': pw}).text) 


    def view(self, token, pw):
        logging.info(f"Viewing token {token} with password {pw}")
        resp = requests.post(f'{self.base_url}/', data={'token': token, 'pw': pw}).text

        if "Wrong" in resp:
            return ""
        return find_message(requests.post(f'{self.base_url}/', data={'token': token, 'pw': pw}).text)

    def get_id(self, token):
        logging.info(f"Get ID of {token}")
        resp = requests.post(f'{self.base_url}/', data={'token': token, 'pw': secrets.token_hex(16)}).text
        s = re.search(r"ID:\s*(\d+)", resp)
        if s == None:
            raise NotFound("Did not find id")
        s = s.group(1)
        if s == None:
            raise NotFound("Did not find id")
        return s

    
    # creates a secret text, returns the managment token
    def create_text(self, text, password):
        logging.info(f"Create Text with password {password}")
        url = self.base_url + '/create'

        form_data = {
            'type': 'text',
            'content': text,
            'pw': password
        }

        response = requests.post(url, data=form_data)
        soup = BeautifulSoup(response.text, 'html.parser')

        token_paragraph = soup.find('p', class_='big')
        if token_paragraph:
            token = token_paragraph.text
            logging.info(f"Generated Token: {token}")
        else:
            logging.error("Token not found in the response.")
            raise NotFound('No Token found on website after creating one')

        return token
    
    # creates a new token with permissions, returns the new token
    def create_token(self, token, password, new_password, permissions = 'read'):
        logging.info(f"Create {permissions} Token with password {new_password}")
        url = self.base_url + '/manage'

        if permissions not in ['read', 'manage']:
            raise Exception('Wrong permissions')

        form_data = {
            'token': token,
            'pw': password,
            'action': permissions,
            'newpw': new_password
        }

        response = requests.post(url, data=form_data)
        soup = BeautifulSoup(response.text, 'html.parser')

        token_paragraph = soup.find('p', class_='big')
        if token_paragraph:
            token = token_paragraph.text
            logging.info(f"Generated Token: {token}")
        else:
            logging.error("Token not found in the response.")
            raise NotFound('No Token found on website after creating one')

        return token


    def place_flag(self, tick):
        flag = checkerlib.get_flag(tick)
        password = secrets.token_hex(16)

        # create texttoken
        try:
            if not (token := self.create_text(flag, password)):
                logging.error("Text token creation failed")
                return checkerlib.CheckResult.FAULTY
        except NotFound:
            logging.error("Text token creation failed")
            return checkerlib.CheckResult.FAULTY

        # create readtoken
        try:
            if not (readtoken := self.create_token(token, password, password)):
                logging.error("Read token creation failed")
                return checkerlib.CheckResult.FAULTY
        except NotFound:
            logging.error("Read token creation failed")
            return checkerlib.CheckResult.FAULTY

        logging.info("Save tokens for tick")
        checkerlib.store_state(str(tick), (readtoken, password))

        logging.info("Set flagid")
        if len(readtoken) > 200:
            logging.error("Createt is Token is too big (longer than 170 bytes)")
            return checkerlib.CheckResult.FAULTY
        checkerlib.set_flagid(f'{{"token": "{readtoken}"}}')

        logging.info("Place flag done")
        return checkerlib.CheckResult.OK

    def check_service(self):

        # check that id is returned on false password
        msg = utils.generate_message()
        pw = secrets.token_hex(16)
        
        try:
            id, token = self.create(msg, pw)
            
        except NotFound:
            logging.error("Read token creation failed")
            return checkerlib.CheckResult.FAULTY
        
        try:
            id2 = self.get_id(token)
        except NotFound:
            logging.error("Could not retrieve id of created read token")
            return checkerlib.CheckResult.FAULTY
        
        #print(id2)

        if id != id2:
            logging.error("Wrong id is returned when wrong password is used")
            return checkerlib.CheckResult.FAULTY


        # generate a new id to check if all ids differ and are close to each other (max diff of 50)
        msg = utils.generate_message()
        pw = secrets.token_hex(16)
        
        
        try:
            new_id, _ = self.create(msg, pw)
        except NotFound:
            logging.error("Read token creation failed")
            return checkerlib.CheckResult.FAULTY

        if new_id == id:
            logging.error("Two differents tokens where created that shared the SAME id.")
            return checkerlib.CheckResult.FAULTY
        if abs(int(new_id) - int(id)) > 50:
            logging.error("The ids are not given away in order. (a diff greater than 50 between two just created tokens)")
            return checkerlib.CheckResult.FAULTY

        return checkerlib.CheckResult.OK

    def check_flag(self, tick):
        flag = checkerlib.get_flag(tick)
        state = checkerlib.load_state(str(tick))
        if not state:
            return checkerlib.CheckResult.FLAG_NOT_FOUND
        token, password = state

        #check that flag is still there
        try:
            msg = self.view(token, password)
        except NotFound:
            logging.error('Could not find the message (that should be the flag) on the website')
            return checkerlib.CheckResult.FLAG_NOT_FOUND

        if not msg == flag:
            return checkerlib.CheckResult.FLAG_NOT_FOUND


        return checkerlib.CheckResult.OK


if __name__ == '__main__':

    checkerlib.run_check(TemplateChecker)

    #Test area:
    """
    c = TemplateChecker('127.0.0.1', 1)
    t = c.create_text('aaa', 'bbb')
    rt = c.create_token(t, 'bbb', 'ccc')
    print(rt)
    """
