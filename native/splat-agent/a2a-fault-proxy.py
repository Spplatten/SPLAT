"""Local proof-only transport fault injector; forwards authentication bytes without holding keys."""
import asyncio
import json
import threading


class FaultProxy:
    def __init__(self, upstream_port, marker):
        self.upstream_port, self.marker = upstream_port, marker
        self.ready = threading.Event()
        self.loop = self.server = self.task = None
        self.error = None
        self.active = 0
        self.drops = []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(5) or self.error:
            raise RuntimeError("local fault proxy startup failed") from self.error

    def stop(self):
        if self.loop and self.task and not self.task.done():
            self.loop.call_soon_threadsafe(self.task.cancel)
        if self.thread.ident:
            self.thread.join(5)
            assert not self.thread.is_alive(), "fault proxy did not stop"

    def run(self):
        try:
            asyncio.run(self.serve())
        except asyncio.CancelledError:
            pass
        except Exception as error:
            self.error = error
            self.ready.set()

    async def serve(self):
        self.loop, self.task = asyncio.get_running_loop(), asyncio.current_task()
        self.server = await asyncio.start_server(self.connection, "127.0.0.1", 50051, limit=1048576)
        async with self.server:
            self.ready.set()
            await self.server.serve_forever()

    async def connection(self, reader, writer):
        if self.active >= 64:
            writer.close()
            return
        self.active += 1
        upstream_writer = None
        tasks = []
        selected = {}
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", self.upstream_port, limit=1048576)

            async def pump(source, destination, outgoing):
                while line := await asyncio.wait_for(source.readline(), timeout=45):
                    envelope = json.loads(line)
                    if outgoing and envelope.get("type") == "AUTHENTICATED":
                        request = json.loads(envelope["request"])
                        if request.get("type") == "EXECUTE_BOUND" and self.marker.exists():
                            boundary = self.marker.read_text()
                            assert boundary in ("POLICY_APPLIED", "EXIT")
                            self.marker.unlink()
                            selected.update(boundary=boundary, mission=request["missionId"])
                    elif not outgoing and envelope.get("type") == "PROVEN" and selected:
                        frame = json.loads(envelope["frame"])
                        if frame.get("type") == selected["boundary"]:
                            self.drops.append(dict(selected))
                            # Lose exactly this authenticated connection. The next connection may
                            # recover its signed receipt, but is never allowed an implicit replay.
                            return
                    destination.write(line)
                    await destination.drain()

            tasks = [asyncio.create_task(pump(reader, upstream_writer, True)),
                     asyncio.create_task(pump(upstream_reader, writer, False))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            for stream in (writer, upstream_writer):
                if stream:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
            self.active -= 1
