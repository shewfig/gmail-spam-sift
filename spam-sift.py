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
from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools

import sys
import pdb
import base64
import email
from apiclient import errors

import re
from collections import Counter

from HTMLParser import HTMLParser

# tweakable variables
tooFew = 5
tooMany = 35
justRight = 20

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()



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
  except errors.HttpError, error:
    print('An error occurred: %s' % error)


def getThreadSubjects(service, user_id, threads):
  subWordLoL = []
  bodyWordLoL = []
  iterNum = 0
  try:
    import base64
    for threadId in threads:
      iterNum += 1
      print(str(iterNum)) if iterNum % 10 == 0 else print('.', end='')
      tdata = service.users().threads().get(userId=user_id, id=threadId['id']).execute()
      #msg = tdata['messages'][0]['payload']
      for header in tdata['messages'][0]['payload']['headers']:
          if header['name'] == 'Subject':
            #print("Found subject: " + header['value'])
            #subWordLoL.extend(header['value'])
            subWordLoL.append(GetText(header['value']))
            break
      for msg in tdata['messages']:
        body = msg['payload']['body']
        if body['size'] > 0:
            if isinstance(body['data'], unicode):
                b64 = base64.urlsafe_b64decode(str(body['data']))
            else:
                b64 = base64.urlsafe_b64decode(str(body['data'].encode("utf8")))
            bodyText=GetText(b64)
            bodyWordLoL.append(bodyText)
            #import pdb
            #pdb.set_trace()
    print(str(iterNum))
    return subWordLoL, bodyWordLoL
  except errors.HttpError, error:
    print('An error occurred: %s' % error)
  except TypeError, error:
    import pdb
    pdb.set_trace()
      



def getUserAddress(service, user_id='me'):
    try:
        response = service.users().getProfile(userId=user_id).execute()
        #pdb.set_trace()
        return response['emailAddress']

    except errors.HttpError, error:
        print('An error occurred: %s' % error)


def unwrap(payload):
    text = base64.urlsafe_b64decode(payload.encode('ascii'))
    return text



def GetText(payload):
    text = strip_tags(payload)
    wordlist = re.findall(r'[A-Za-z0-9\']+', text.lower())
    return wordlist


def make_tuples_from_list_of_lists(size, corpus):
    retList = []
    if size < 2:
        badList = [u'http', u'html', u'www', u'com', u's', u't', u'gmail', u'hi']
        try:
            from nltk.corpus import stopwords
            stop_words = list(stopwords.words('english'))
            badList.extend(stop_words)
        except LookupError:
            import nltk
            from tempfile import mkdtemp
            from shutil import rmtree
            nltkTmpDir = mkdtemp()
            nltk.data.path = [ nltkTmpDir ]
            nltkDl = nltk.downloader.Downloader(download_dir=nltkTmpDir)
            nltkDl.download(info_or_id='stopwords')
            stop_words = list(stopwords.words('english'))
            # some basic sanity, but /shrug
            if len(nltkTmpDir) > 4 and not nltkTmpDir.endswith('/'):
                rmtree(nltkTmpDir)
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
        for thisList in corpus:
            # create a set per message to get unique tuples for that message
            thisTupList = set()
            # make a list of all tuples (markhov chains)
            for i in range(len(thisList)-(size-1)):
                thisTupList.add('+'.join(thisList[i + x] for x in range(size) ))
            # add per-message set of chains to the return list
            retList.extend(list(thisTupList))
    return retList

    
def showNTell(mChain):
    import webbrowser
    mUrl = "https://mail.google.com/mail/u/0/"

    if mChain is not None:
        mUrl += "#search/in%3Aspam+" + str(mChain)
    else:
        mUrl += "#spam"
    
    webbrowser.open(url = mUrl, autoraise=True)
    exit(0)

def countMessagesWithTuple(mChain, service, user_id='me'):
    if mChain is not None:
      query = "in:spam AND NOT(label:trash) AND " + str(mChain) + "\""
      try:
        response = service.users().messages().list(userId=user_id,
                                                   q=query).execute()
        messages = []
        if 'messages' in response:
          messages.extend(response['messages'])

        while 'nextPageToken' in response:
          try:
              page_token = response['nextPageToken']
              response = service.users().messages().list(userId=user_id, q=query,
                                                 pageToken=page_token).execute()
              messages.extend(response['messages'])
          except:
              import pdb
              pdb.set_trace()

        #print(str(len(messages))+": \""+mChain+"\"")
        return len(messages)
      except errors.HttpError, error:
        print('An error occurred: %s')% error
    
    
# Setup the Gmail API
SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
#SCOPES = 'https://www.googleapis.com/auth/gmail.metadata'
store = file.Storage('credentials.json')
creds = store.get()
if not creds or creds.invalid:
    flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
    creds = tools.run_flow(flow, store)
service = build('gmail', 'v1', http=creds.authorize(Http()))

print("Getting user info")
useraddr = str(getUserAddress(service, 'me'))
print("User address = "+useraddr)

print("Retrieving messages")
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

    # improve hit visual efficicency
    justRight = min(justRight, len(threads)//2)
    minHit = min(max(tooFew, tooFew + (abs(justRight - tooFew)//2)),len(threads))
    maxHit = min(min(tooMany, tooMany - (abs(tooMany - justRight)//2)),len(threads))
    print("Low: "+str(minHit)+", High: "+str(maxHit))

    # Try snippet list first, it's fast
    wordList = []
    for thread_id in threads:
        msgWords = list(GetText(thread_id['snippet']))
        #wordList.extend(msgWords)
        wordList.append(["can't" if x=="cant" else "don't" if x=="dont" else x for x in msgWords])

    maxTupleSize=6

    # track it all
    wordCounter = Counter()

    # Test multi-word combos in decreasing length until:
    # Happy: there's a common enough result
    # Unhappy: we're going word by word
    # prime the loop
    subWords = []
    bodyWords = []
    tupSize = maxTupleSize
    # print("Target: "+str(tooFew))
    # loop
    for phase in range(2,-1,-1):
        hitCount = 0

        print("hitCount: " + str(hitCount) + ", phase: " + str(phase) + ", tupSize: " + str(tupSize))
        while tupSize >= phase:
        #while tupSize > 1:
            # +1 count of all previous results
            wordCounter.update(list(wordCounter))
            tupSize-=1
            tuples = make_tuples_from_list_of_lists(tupSize, wordList)
            if len(tuples)>0:
                tupCounter = Counter(tuples)
                wordCounter.update(Counter(el for el in tupCounter.elements() if tupCounter[el] > tooFew))
                #hitCount = countMessagesWithTuple(tupCounter.most_common(1)[0][0], service, 'me')
                hitCount = tupCounter.most_common(1)[0][1]
                print("Tuple("+str(tupSize)+"): "+str(hitCount)+"/"+str(minHit)+" \""+tupCounter.most_common(1)[0][0]+"\"")
        #import pdb
        #pdb.set_trace()

        next if len(wordCounter)==0 else print("Most hits: "+str(wordCounter.most_common(1)[0][1]))

        for low, high in zip([minHit, tooFew], [maxHit, tooMany]):
            # Find a tuple in the Goldilocks zone
            print("Low: "+str(low)+", High: "+str(high))
            #for k, v in wordCounter.most_common(min(10,len(wordCounter))):
            for k, v in wordCounter.most_common():
                if v <= high:
                    realV = countMessagesWithTuple(k, service, 'me')
                    #realV = v
                    print("Snippet:\""+str(k)+"\": "+str(v)+". Text: "+str(low)+" < "+str(realV)+" < "+str(high))
                    if low <= realV <= high:
                        showNTell(k)
                        break

        if len(subWords) < 1:
          # Go and pull all of the subjects too
          print("Loading " + str(len(threads)) + " messages.")
          subjLoL, bodyLoL = getThreadSubjects(service, 'me', threads)
          for msgWords in subjLoL:
            #subWords.extend(msgWords)
            subWords.append(msgWords)
          for msgWords in bodyLoL:
            bodyWords.append(msgWords)
          #pdb.set_trace()
          wordList.extend(subWords)
          wordCounter = Counter()
          tupSize = maxTupleSize
        #else:
          #wordList.extend(bodyWords)
          #wordCounter = Counter()
          #tupSize = maxTupleSize

# Just load all messages
showNTell(None)
