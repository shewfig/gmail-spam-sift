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

from wordfreq import zipf_frequency, tokenize

import sys
import base64
from googleapiclient import errors

from collections import Counter

from lxml import html
from lxml.html.clean import clean_html

import webbrowser

def strip_tags(payload):
    if isinstance(payload, str) and len(payload)>1:
        try:
            tree = html.fromstring(payload)
            return str(clean_html(tree).text_content().strip())
        except:
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
            bodyWordsList.append(bodyText)
    return subjWordsList, bodyWordsList
  except errors.HttpError as error:
    print('An error occurred: %s' % error)
      



def getUserAddress(service, user_id='me'):
    try:
        response = service.users().getProfile(userId=user_id).execute()
        return response['emailAddress']

    except errors.HttpError as error:
        print('An error occurred: %s' % error)


def unwrap(payload):
    text = base64.urlsafe_b64decode(payload.encode('ascii'))
    return text



def GetText(payload):
    text = strip_tags(payload)
    wordlist = tokenize(text.lower(), 'en')
    return [ele for ele in wordlist if ele.encode('ascii', 'ignore').strip()]



def make_tuples_from_list_of_lists(size, corpus):
    retList = []

    thisTupList = set()
    for thisList in corpus:
        if (type(thisList) is not list) or (len(thisList) == 0) or (len(thisList) < size):
            next
        else:
            #print(str(thisList))

            # turn each message into a set to de-dupe words w/in message and count instances across messsages
            if size == 1:
                retList.extend(set(thisList))

            else:
                # create a set per message to get unique tuples for that message
                thisTupList.clear()
                # make a list of all tuples (markhov chains)
                for i in range(len(thisList)-(size-1)):
                    try:
                        thisTup = [str(thisList[i + x]) for x in range(size)]
                        if len(thisTup) != size:
                            next
                        elif len(max(thisTup, key=len)) == 1:
                            thisTupStr = ''.join(thisTup)
                            #breakpoint()
                        else:
                            thisTupStr = ' '.join(thisTup)
                        thisTupList.add(thisTupStr)
                        #print("Adding: "+thisTupStr)
                    except:
                        breakpoint()
                # add per-message set of chains to the return list
                retList.extend(list(thisTupList))
    return retList

    
def showNTell(mChain, emailAddr=None):
    mUrl = "https://mail.google.com/mail{authstr}".format(authstr="/u/0/" if emailAddr is None else "?authuser="+emailAddr)

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
        elif k in str(getUserAddress(service, 'me')).split('@') \
                or k == str(getUserAddress(service, 'me')).replace('@', ' '):
                    '''
                    print("\nKeyword is username({keyword}), skipping"\
                            .format(keyword=k))
                    #'''
                    continue
        else:
            realV = countMessagesWithTuple(k, service, 'me')
            thisRare = getTupScore(k)
            thisLow = max((low - thisRare),lowest)
            thisHigh = (high + thisRare)
            thisV = realV
            highest = max(realV, highest)
            if realV < 1:
                del tupCounter[k]
            elif thisLow <= thisV <= thisHigh:
                print("\n[{hits} @ {score}z] \"{keyword}\"".format(hits=realV, keyword=k, score=thisRare))
                showNTell(k, str(getUserAddress(service, 'me')))
            else:
                """
                print("\n[{fakeIn}: {low} < {val} < {high}]: {term}"\
                    .format(\
                    low=thisLow, high=thisHigh,\
                    fakeIn=v, val=thisV,\
                    term=k \
                    ))
                #"""
                tupCounter[k]=realV
    print("\nMax hits: {hits}".format(hits=highest))
    #walkCounter(tupCounter, low, high)

def walkCounter(tupCounter, service, low, high):
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
                showNTell(k, str(getUserAddress(service, 'me')))

def getTupScore(tup, commonList=['unsubscribe','click']):
    return round(sum(7 - (zipf_frequency(term, 'en') if term not in commonList else 6) for term in tokenize(tup, 'en'))*5)
    
if __name__ == '__main__':
    # Running as the main program ...

    # tweakable variables
    absoluteMin = 5
    tooMany = 50
    justRight = 34
    
    myBrowser = 'chrome'

    # Setup the Gmail API
    SCOPES = [ 'https://www.googleapis.com/auth/gmail.readonly' ]
    #SCOPES = 'https://www.googleapis.com/auth/gmail.metadata'

    # Set preferred browser (if any)
    # #WARNING this method is not documented, ergo not recommended
    if myBrowser is not None:
        webbrowser.register_standard_browsers()
        if myBrowser in webbrowser._tryorder:
            webbrowser._os_preferred_browser = myBrowser
        else:
            os.environ["BROWSER"] = myBrowser
        webbrowser._tryorder = None

    # Oauth flaming hoops
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
    elif len(threads) < absoluteMin:
        print("Only "+str(len(threads))+" messages")

    else:
        print("Found "+str(len(threads))+" messages")

        if len(threads) < tooMany:
            tooMany = len(threads)

        #maxTupleSize=int(len(threads) ** (1/3))
        maxTupleSize=min(int((len(threads) ** (1/2)/2)),6)
        print("Max tuple size: "+str(maxTupleSize))

        # improve hit visual efficicency
        #justRight = min(justRight, len(threads)//2)
        #localMin = min(max(absoluteMin, absoluteMin + (abs(justRight - absoluteMin)//2)),len(threads))
        #maxHit = min(min(tooMany, tooMany - (abs(tooMany - justRight)//2)),len(threads))
        localMin = min((absoluteMin + absoluteMin + len(threads)//2)//3,justRight)
        maxHit = (tooMany + tooMany + len(threads)//2)//3
        print("Low: "+str(localMin)+", High: "+str(maxHit + (maxTupleSize ** 2)))

        # Try snippet list first, it's fast
        wordList = []
        for thread_id in threads:
            msgWords = GetText(thread_id['snippet'])
            #wordList.extend(msgWords)
            # wordList.append(["can't" if x=="cant" else "don't" if x=="dont" else x for x in msgWords])
            wordList.append(msgWords)

        # track it all
        wordCounter = Counter()

        # Test multi-word combos in decreasing length until:
        # Happy: there's a common enough result
        # Unhappy: we're going word by word
        # prime the loop
        # loop

        subjList = None
        bodyList = None

        for scope in ['snippets','subjects','bodies']:
            print("Now parsing: "+scope)

            tupSize = maxTupleSize
            hitCount = 0

            while tupSize > 0:
                # +1 count of all previous results
                # DISABLED because rareness provides the bias now
                # wordCounter.update(list(wordCounter))
                tuples = make_tuples_from_list_of_lists(tupSize, wordList)
                if len(tuples)>0:
                    tupCounter = Counter(tuples)
                    hitCount = tupCounter.most_common(1)[0][1]

                    for tup in tupCounter:
                        tupCounter[tup] *= \
                            ( \
                            getTupScore(tup,commonList=[tokenize(useraddr, 'en'),'unsubscribe','click']) \
                            if tupCounter[tup] >= absoluteMin else 0 \
                            ) 

                    try:
                        print("Tuple({tupSize}): {hitCount}/{localMin} \"{mcword}\" ({tscore})"\
                            .format(tupSize=tupSize, hitCount=hitCount, localMin=localMin, \
                            mcword=tupCounter.most_common(1)[0][0], tscore=tupCounter.most_common(1)[0][1]))
                    except:
                        breakpoint()
                    wordCounter.update(Counter(el for el in tupCounter.elements() if (tupCounter[el] > 1)))
                tupSize-=1

            # after this point, wordCounter should be "clean" and need no additional API hits
                
            if len(wordCounter)>0:
                cleanCounter(wordCounter, service, localMin, max(maxHit, 95), absoluteMin)
                #walkCounter(wordCounter, absoluteMin, len(threads)//2)

            if scope == "snippets":
                print("Loading " + str(len(threads)) + " messages.")
                subjList, bodyList = getThreadSubjects(service, 'me', threads)
                #print("Adding subjects to search space")
                #wordList.extend(list(GetText(wl) for wl in subjList))
                print("Switching search space to subjects")
                for thisSubj in subjList:
                    wordList.extend(GetText(thisSubj))
            elif scope == "subjects":
                #print("Adding bodies to search space")
                #wordList.extend(list(GetText(wl) for wl in bodyList))
                print("Switching search space to bodies")
                for thisBody in bodyList:
                    wordList.extend(GetText(thisBody))

            wordCounter.clear()
            tupSize = maxTupleSize
            #breakpoint()

    # Just load all messages
    showNTell(None, useraddr)
