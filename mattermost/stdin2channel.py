#!/usr/bin/env python3
"""
Someone's Mattermost API v4 bindings.
  Copyright (c) 2016-2021 by Someone <someone@somenet.org> (aka. Jan Vales <jan@jvales.net>)
  published under MIT-License

post stdin to a channel.
"""

import os
import sys

from inspect import cleandoc

import mattermost


def main():
    show_usage = False
    mm_api = None
    chan_id = None

    if "MM_APIURL" in os.environ:
        mm_api = mattermost.MMApi(os.environ["MM_APIURL"])
    else:
        show_usage = True


    if ("MM_USER" in os.environ and "MM_PASS" in os.environ) or ("MM_BEARER" in os.environ):
        if "MM_BEARER" in os.environ:
            mm_api.login(bearer=os.environ["MM_BEARER"])
        else:
            mm_api.login(os.environ["MM_USER"], os.environ["MM_PASS"])
    else:
        show_usage = True


    if "MM_CHANID" in os.environ:
        chan_id = os.environ["MM_CHANID"]
    else:
        show_usage = True


    if len(sys.argv) < 1 or len(sys.argv) > 3:
        show_usage = True


    if show_usage:
        print(cleandoc("""required ENV-parameters: MM_APIURL, MM_USER+MM_PASS or MM_BEARER, MM_CHANID.
            arguments: [PREFIX] [SUFFIX]
            """))
        sys.exit(1)


    prefix = suffix = ""
    try:
        prefix = sys.argv[1].replace("\\n", "\n")
        suffix = sys.argv[2].replace("\\n", "\n")
    except:
        pass

    print("Posting to channel:" +str(mm_api.create_post(chan_id, prefix+sys.stdin.read()+suffix, props={"from_webhook":"true"})))

    mm_api.logout()


if __name__ == '__main__':
    main()
