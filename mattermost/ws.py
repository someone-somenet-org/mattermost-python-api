#!/usr/bin/env python3
"""
Someone's Mattermost API v4 bindings.
  Copyright (c) 2016-2021 by Someone <someone@somenet.org> (aka. Jan Vales <jan@jvales.net>)
  published under MIT-License
"""

import logging
import json
import asyncio
import threading
import traceback
import websockets

logger = logging.getLogger("mattermost.ws")


class MMws:
    """
    Websocket client.
    """

    def __init__(self, ws_handler, api, ws_url):
        self.api = api
        self.ws_url = ws_url
        self.ws_handler = ws_handler
        self.loop = asyncio.new_event_loop()

        self._new_websocket_thread()


    def close_websocket(self):
        """
        Close the websocket and invalidate this object.
        """
        self.loop.stop()
        self.loop = None


    def _new_websocket_thread(self):
        if self.loop is None:
            return

        thread = threading.Timer(3.0, self._open_websocket)
        thread.setDaemon(True)
        thread.setName("websocket")
        thread.start()


    def _open_websocket(self):
        try:
            self.loop.run_until_complete(self._websocket_run())
        except:
            if self.loop:
                logger.info("websocket failed. restarting...")
                logger.error("".join(traceback.format_exc()))

        self._new_websocket_thread()


    async def _websocket_run(self):
        logger.info("Starting websocket client.")
        async with websockets.connect(self.ws_url) as websocket:
            await websocket.send(json.dumps({"seq": 1, "action":"authentication_challenge", "data":{"token":self.api._bearer}}))
            logger.info("websocket client connected")

            while self.loop:
                data = json.loads(await websocket.recv())
                if "event" not in data:
                    continue

                try:
                    self.ws_handler(self, data)
                except:
                    logger.error("".join(traceback.format_exc()))
