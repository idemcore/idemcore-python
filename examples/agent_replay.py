# SPDX-License-Identifier: Apache-2.0
"""Record a small tool-using agent, verify the trace offline, then replay it.

    export IDEMCORE_API_KEY=...        # never commit it
    python examples/agent_replay.py record run.trace.json
    python -m idemcore trace verify run.trace.json
    python examples/agent_replay.py replay run.trace.json

The agent asks the model which city to look up, calls a (fake) weather tool,
then asks the model to write a one-line forecast from the tool result.
On replay the agent code runs again: model calls go to the API and must come
back bit-identical; the weather tool is NOT called; its recorded result is used.
"""
import json
import sys

import idemcore
from idemcore import trace

MODEL = None  # server default


def get_weather(city: str) -> dict:
    # A real tool would call a weather API; its answer changes over time, which
    # is exactly why replay feeds the recorded result instead of calling it again.
    return {"city": city, "temp_c": 18, "sky": "light rain"}


def agent(s: trace.Session) -> str:
    q = [{"role": "system", "content": "Answer with one city name only."},
         {"role": "user", "content": "Which city is the Eiffel Tower in?"}]
    city = s.chat(q, model=MODEL, max_tokens=8).text.strip().strip(".")
    w = s.tool("get_weather", {"city": city}, get_weather)
    q2 = [{"role": "user", "content": f"Weather data: {json.dumps(w, sort_keys=True)}. "
                                      "Write a one-sentence forecast."}]
    return s.chat(q2, model=MODEL, max_tokens=40).text


def main() -> int:
    cmd, path = sys.argv[1], sys.argv[2]
    client = idemcore.Idemcore()
    if cmd == "record":
        s = trace.Session(client, meta={"example": "agent_replay"})
        print(agent(s))
        s.save(path)
        print("saved", path, "head", s.head[:16])
        return 0
    rep = trace.replay(trace.load_trace(path), client, agent=agent)
    print(rep.summary())
    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
