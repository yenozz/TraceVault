import io
import sys
import httpx
import trio
from holehe.core import get_functions, import_submodules, launch_module


async def _run_holehe(email):
    modules = import_submodules("holehe.modules")
    websites = get_functions(modules)
    client = httpx.AsyncClient()
    out = []
    async with trio.open_nursery() as nursery:
        for website in websites:
            nursery.start_soon(launch_module, website, email, client, out)
    await client.aclose()
    return sorted(out, key=lambda i: i["name"])


def get_info_mail(email):
    try:
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            results = trio.run(_run_holehe, email)
        finally:
            sys.stderr = old_stderr
        found = [r for r in results if r.get("exists")]
        not_found = [r for r in results if not r.get("exists") and not r.get("rateLimit")]
        return {
            "email": email,
            "trouve_sur": found,
            "total_trouve": len(found),
            "total_verifie": len(results)
        }
    except Exception as e:
        return {"error": str(e)}
