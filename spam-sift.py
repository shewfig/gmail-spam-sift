#!/usr/bin/env python

# Portions Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at #
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START gmail_quickstart]
"""
Use Gmail API to pull snippets of all spam threads
then make markhov chains from all messages
and use most frequent chains to view subset of spam

Multiple decisions of fewer related spam messages is easier than a single decision of all messages
"""

from __future__ import print_function
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import google.auth.exceptions

from httplib2 import Http
from oauth2client import file, client, tools

import sys
import pdb
import base64
import email
from googleapiclient import errors

import re
from collections import Counter

# tweakable variables
tooFew = 5
tooMany = 50
justRight = 34

from lxml import html
from lxml.html.clean import clean_html

def strip_tags(payload):
    if isinstance(payload, str) and len(payload)>1:
        try:
            tree = html.fromstring(payload)
            return str(clean_html(tree).text_content().strip())
        except:
            #pdb.set_trace()
            return str(payload)
    else:
        return str(payload) 


def ListThreadsWithLabels(service, user_id, label_ids=[]):
  try:
    response = service.users().threads().list(userId=user_id,
                                               labelIds=label_ids).execute()
    threads = []
    if 'threads' in response:
      threads.extend(response['threads'])

    while 'nextPageToken' in response:
      page_token = response['nextPageToken']
      response = service.users().threads().list(userId=user_id,
                                                 labelIds=label_ids,
                                                 pageToken=page_token).execute()
      threads.extend(response['threads'])

    return threads
  except errors.HttpError as error:
    print('An error occurred: %s' % error)


def getThreadSubjects(service, user_id, threads):
  subjWordsList = []
  bodyWordsList = []
  iterNum = 0
  try:
    import base64
    for threadId in threads:
      iterNum += 1
      amtDone = iterNum/float(len(threads))
      progBar(amtDone,"Downloading Messages")
      #print(str(iterNum)) if iterNum % 10 == 0 else print('.', end='')
      tdata = service.users().threads().get(userId=user_id, id=threadId['id']).execute()
      #msg = tdata['messages'][0]['payload']
      for header in tdata['messages'][0]['payload']['headers']:
          if header['name'] == 'Subject':
            #print("Found subject: " + header['value'])
            #subjWordsList.extend(header['value'])
            subjWordsList.append(header['value'])
            break
      for msg in tdata['messages']:
        body = msg['payload']['body']
        if body['size'] > 0:
            if isinstance(body['data'], str):
                bodyText = base64.urlsafe_b64decode(str(body['data']))
            else:
                bodyText = base64.urlsafe_b64decode(str(body['data'].encode("utf8")))
            #bodyText=GetText(b64)
            #pdb.set_trace()
            bodyWordsList.append(bodyText)
    return subjWordsList, bodyWordsList
  except errors.HttpError as error:
    print('An error occurred: %s' % error)
      



def getUserAddress(service, user_id='me'):
    try:
        response = service.users().getProfile(userId=user_id).execute()
        #pdb.set_trace()
        return response['emailAddress']

    except errors.HttpError as error:
        print('An error occurred: %s' % error)


def unwrap(payload):
    text = base64.urlsafe_b64decode(payload.encode('ascii'))
    return text



def GetText(payload):
    text = strip_tags(payload)
    wordlist = re.findall(r'[A-Za-z0-9\']+', text.lower())
    #wordlist = text.lower().split()
    #pdb.set_trace()
    return [ele for ele in wordlist if ele.encode('ascii', 'ignore').strip()]


def cleanup_nltk_at_exit(nltkTmpDir):
    # some basic sanity, but /shrug
    if len(nltkTmpDir) > 4 and not nltkTmpDir.endswith('/'):
        print("Cleaning up downloaded file(s)")
        from shutil import rmtree
        rmtree(nltkTmpDir)


def make_tuples_from_list_of_lists(size, corpus):
    retList = []
    badList = ['http', 'href', 'html', 'www', 'com', 's', 't', 'gmail', 'hi', 'doctype', 'w3c', 'dtd', 'https']
    if size < 2:
        try:
            from nltk.corpus import stopwords
            stop_words = list(stopwords.words('english'))
            badList.extend(stop_words)
        except:
            import atexit
            import nltk
            from tempfile import mkdtemp
            nltkTmpDir = mkdtemp()
            nltk.data.path = [ nltkTmpDir ]
            nltkDl = nltk.downloader.Downloader(download_dir=nltkTmpDir)
            nltkDl.download(info_or_id='stopwords')
            stop_words = list(stopwords.words('english'))
            atexit.register(cleanup_nltk_at_exit, nltkTmpDir)
            badList.extend(stop_words)

        # create a set per message to get unique words for that message
        # then add each set to list so Counter will count messages
        if size == 1:
            for thisList in corpus:
                retList.extend(set(w for w in thisList if w not in badList))

        # tupsize 0: return all of the common words previously excluded
        elif size == 0:
            for thisList in corpus:
                retList.extend(set(w for w in thisList if w in badList))

    else:
        thisTupList = set()
        for thisList in corpus:
            # create a set per message to get unique tuples for that message
            thisTupList.clear()
            # make a list of all tuples (markhov chains)
            for i in range(len(thisList)-(size-1)):
                try:
                    thisTup = (' '.join(thisList[i + x] for x in range(size) if thisList[i+x] not in badList))
                    if len(thisTup.split()) == size:
                        thisTupList.add(thisTup)
                except:
                    pdb.set_trace()
            # add per-message set of chains to the return list
            retList.extend(list(thisTupList))
    return retList

    
def showNTell(mChain):
    #pdb.set_trace()
    import webbrowser
    mUrl = "https://mail.google.com/mail/u/0/"

    if mChain is not None:
        mUrl += "#search/in%3Aspam+" + str(mChain).replace(" ","+")
    else:
        mUrl += "#spam"
    
    #print("URL: "+mUrl)
    webbrowser.open(url = mUrl, autoraise=True)
    exit(0)

def countMessagesWithTuple(mChain, service, user_id='me'):
    if mChain is not None:
      #query = "in:spam AND NOT(label:trash) AND \"" + str(mChain) + "\""
      query = "in:spam AND NOT(label:trash) AND " + str(mChain)
      try:
        response = service.users().threads().list(userId=user_id,
                                                   q=query).execute()
        #print("Key: "+mChain+" Count: "+ str(response['resultSizeEstimate']))
        return response['resultSizeEstimate']
      except errors.HttpError as error:
        print('An error occurred: %s')% error
    
def progBar(amtDone, msg="Progress"):
    barLen = 58 - len(msg)
    sys.stdout.write("\r{msg}: [{hashBar:{barWid}{type}}] {pctDone:.1f}%".format(hashBar='#' * int(amtDone * barLen), barWid=barLen, pctDone=amtDone*100, msg=msg, type="s"))
    sys.stdout.flush()
    if amtDone == 1:
        print()

def cleanCounter(tupCounter, service, low, high, lowest):
    if tupCounter.most_common()[0][1] < lowest:
        print("Max count: {0} < floor: {1}, deleting".format(tupCounter.most_common()[0][1],lowest))
        tupCounter.clear()
        return 
    tupCount = len(tupCounter)
    iterNum = 0
    msg="{2} Tuples: {0}-{1}".format(low,high,tupCount)
    highest=0
    for k, v in tupCounter.most_common():
        iterNum += 1
        amtDone = iterNum/float(tupCount)
        progBar(amtDone,msg)
        if v < lowest:
            del tupCounter[k]
        else:
            realV = countMessagesWithTuple(k, service, 'me')
            highest = max(realV, highest)
            if realV < 1:
                del tupCounter[k]
            elif low <= realV <= high:
                print("\n[{hits}] \"{keyword}\"".format(hits=realV, keyword=k))
                showNTell(k)
            else:
                tupCounter[k]=realV
    print("\nMax hits: {hits}".format(hits=highest))
    #walkCounter(tupCounter, low, high)

def walkCounter(tupCounter, low, high):
    tupCount = len(tupCounter)
    iterNum = 0
    msg="{2} Tuples: {0}-{1}".format(low,high,tupCount)
    for k, realV in tupCounter.most_common():
        iterNum += 1
        amtDone = iterNum/float(tupCount)
        progBar(amtDone,msg)
        if low <= realV:
            if realV <= high:
                print("\n[{hits}] \"{keyword}\"".format(hits=realV, keyword=k))
                showNTell(k)
    
# Setup the Gmail API
SCOPES = [ 'https://www.googleapis.com/auth/gmail.readonly' ]
#SCOPES = 'https://www.googleapis.com/auth/gmail.metadata'

creds = None
# The file token.json stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
if os.path.exists('token.json'):
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
# If there are no (valid) credentials available, let the user log in.
if creds and creds.expired and creds.refresh_token:
    try:
        creds.refresh(Request())
    except google.auth.exceptions.RefreshError as error:
        print('Refresh error: %s' % error)
        creds = None
if not creds or not creds.valid:
    flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
# Save the credentials for the next run
with open('token.json', 'w') as token:
    token.write(creds.to_json())

service = build('gmail', 'v1', credentials=creds)

print("Getting user info")
useraddr = str(getUserAddress(service, 'me'))
print("User address = "+useraddr)

print("Loading message snippets")
threads = ListThreadsWithLabels(service, 'me', 'SPAM')

# optimize: only analyze if there are enough messages
if len(threads) == 0:
    print("No messages found")
    exit(0)
elif len(threads) < tooFew:
    print("Only "+str(len(threads))+" messages")

else:
    print("Found "+str(len(threads))+" messages")

    if len(threads) < tooMany:
        tooMany = len(threads)

    #maxTupleSize=int(len(threads) ** (1/3))
    maxTupleSize=int((len(threads) ** (1/2)/2))
    print("Max tuple size: "+str(maxTupleSize))

    # improve hit visual efficicency
    #justRight = min(justRight, len(threads)//2)
    #minHit = min(max(tooFew, tooFew + (abs(justRight - tooFew)//2)),len(threads))
    #maxHit = min(min(tooMany, tooMany - (abs(tooMany - justRight)//2)),len(threads))
    minHit = min((tooFew + tooFew + len(threads)//2)//3,justRight)
    maxHit = (tooMany + tooMany + len(threads)//2)//3
    print("Low: "+str(minHit)+", High: "+str(maxHit + (maxTupleSize ** 2)))

    # Try snippet list first, it's fast
    wordList = []
    for thread_id in threads:
        msgWords = GetText(thread_id['snippet'])
        #wordList.extend(msgWords)
        wordList.append(["can't" if x=="cant" else "don't" if x=="dont" else x for x in msgWords])

    # track it all
    wordCounter = Counter()

    # Test multi-word combos in decreasing length until:
    # Happy: there's a common enough result
    # Unhappy: we're going word by word
    # prime the loop
    subjWords = []
    bodyWords = []
    # print("Target: "+str(tooFew))
    # loop
    tupSize = maxTupleSize
    hitCount = 0

    while tupSize > 0:
        # +1 count of all previous results
        wordCounter.update(list(wordCounter))
        tuples = make_tuples_from_list_of_lists(tupSize, wordList)
        if len(tuples)>0:
            tupCounter = Counter(tuples)
            hitCount = tupCounter.most_common(1)[0][1]
            print("Tuple("+str(tupSize)+"): "+str(hitCount)+"/"+str(minHit)+" \""+tupCounter.most_common(1)[0][0]+"\"")
            if hitCount > max(tooFew, (minHit - (tupSize * 2))):
                cleanCounter(tupCounter, service, max(tooFew, (minHit - (tupSize * 2))), max(maxHit + (tupSize ** 2), min(95,maxHit)), tooFew)
            wordCounter.update(Counter(el for el in tupCounter.elements() if (tupCounter[el] > tooFew)))
        tupSize-=1

    # after this point, wordCounter should be "clean" and need no additional API hits
        
    if len(wordCounter)>0:
        #walkCounter(wordCounter, service, tooFew, len(threads)//2, tooFew)
        walkCounter(wordCounter, tooFew, len(threads)//2)

    print("Loading " + str(len(threads)) + " messages.")
    subjList, bodyList = getThreadSubjects(service, 'me', threads)
    print("Adding subjects to search space")
    wordList.extend(list(GetText(wl) for wl in subjList))
    wordCounter.clear
    tupSize = maxTupleSize

    while tupSize > 0:
        # +1 count of all previous results
        wordCounter.update(list(wordCounter))
        tuples = make_tuples_from_list_of_lists(tupSize, wordList)
        if len(tuples)>0:
            tupCounter = Counter(tuples)
            hitCount = tupCounter.most_common(1)[0][1]
            print("Tuple("+str(tupSize)+"): "+str(hitCount)+"/"+str(minHit)+" \""+tupCounter.most_common(1)[0][0]+"\"")
            cleanCounter(tupCounter, service, minHit, maxHit, tooFew)
            wordCounter.update(Counter(el for el in tupCounter.elements() if (tupCounter[el] > tooFew)))
        tupSize-=1
        
    if len(wordCounter)>0:
        #walkCounter(wordCounter, service, tooFew, len(threads)//2, tooFew)
        walkCounter(wordCounter, tooFew, len(threads)//2)

#    print("Adding bodies to search space")
#    wordList.extend(list(GetText(wl) for wl in bodyList))
#    wordCounter.clear
#    tupSize = maxTupleSize
#
#    tupSize = 5
#    while tupSize > 1:
#        # +1 count of all previous results
#        wordCounter.update(list(wordCounter))
#        tuples = make_tuples_from_list_of_lists(tupSize, wordList)
#        if len(tuples)>0:
#            tupCounter = Counter(tuples)
#            wordCounter.update(Counter(el for el in tupCounter.elements() if (tupCounter[el] > tooFew)))
#            hitCount = tupCounter.most_common(1)[0][1]
#            print("Tuple("+str(tupSize)+"): "+str(hitCount)+"/"+str(minHit)+" \""+tupCounter.most_common(1)[0][0]+"\"")
#            print("Testing %d tuples"%len(tupCounter))
#            #walkCounter(tupCounter, service, minHit, maxHit, tooFew)
#        tupCount = len(tupCounter)
#        print("Tuple(%d): pass 1 = %d"%(tupSize,tupCount))
#        if tupCount>0:
#            tupCounter = Counter(tuples)
#            iterNum=0
#            tupRefCounter = Counter(tupCounter)
#            for el,v in tupRefCounter.items():
#                iterNum += 1
#                amtDone = iterNum/float(tupCount)
#                progBar(amtDone)
#                if v < minHit or v > maxHit:
#                    del tupCounter[el]
#            print("\nTuple(%d): pass 2 = %d"%(tupSize,len(tupCounter)))
#            if len(tupCounter)>0:
#                wordCounter.update(tupCounter)
#                hitCount = tupCounter.most_common(1)[0][1]
#                print("Tuple("+str(tupSize)+"): "+str(hitCount)+"/"+str(minHit)+" \""+tupCounter.most_common(1)[0][0]+"\"")
#                walkCounter(tupCounter, service, minHit, maxHit, tooFew)
#        tupSize-=1
        
# Just load all messages
showNTell(None)
