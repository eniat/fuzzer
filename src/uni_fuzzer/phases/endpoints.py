import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from pathlib import PurePosixPath
from uuid import uuid4

from ..phases.fuzzer_phases import FuzzerPhase, PhaseContext

log = logging.getLogger(__name__)

class EndpointsPhase (FuzzerPhase):
    """
        Runs the endpoint fuzzer/s depending on args
    """

    def __init__(self, run_paths, run_params, run_xss_params, wordlistPathsParams, wordlistXss):
        self.run_paths = run_paths
        self.run_params = run_params
        self.run_xss_params = run_xss_params
        self.wordlistPathsParams = wordlistPathsParams
        self.wordlistXss = wordlistXss

    @property
    def name(self):
        return "Endpoints"


    def prepare(self, ctx: PhaseContext) :
        """
            If path fuzzing then filter for unique endpoints from crawler
        """
        # Build the endpoint list
        if self.run_paths:
            uniqueUrl = {}
            for enp in ctx.endpoints:
                parsedPat = urlparse(enp["url"]).path or "/"
                baseDire = str(PurePosixPath(ctx.runtime.util.get_directories(parsedPat))).rstrip("/")

                if baseDire not in uniqueUrl:
                    uniqueUrl[baseDire] = enp

            ctx.shared["phaseEndpoints"] = list(uniqueUrl.values())
        else:
            ctx.shared["phaseEndpoints"] = ctx.endpoints

        ctx.shared.setdefault("globalVisitedPaths", set())
        ctx.shared.setdefault("globalVisitedFuzzPaths", set())
        ctx.shared.setdefault("globalVisitedLock", threading.Lock())

        # Update visited
        for epoi in ctx.shared["phaseEndpoints"]:
            pa = urlparse(epoi["url"]).path or "/"
            di = ctx.runtime.util.get_directories(pa)
            ctx.shared["globalVisitedPaths"].add(di)


    def run(self, ctx:PhaseContext):
        """
            For the running of the Endpoints Phase
        """
        # Check for wordlists if not set False
        if (self.run_paths or self.run_params) and not self.wordlistPathsParams:
            return []
        if self.run_xss_params and not self.wordlistXss:
            return []

        endpoints = ctx.shared["phaseEndpoints"]

        if not endpoints:
            return []

        args = ctx.args
        cfg = ctx.cfg
        base = ctx.baseUrl
        allVulns = []

        def fuzzEndpoint(endpo, sess):
            """
                To allow for parallel calls
            """

            results = []

            rawUrl = endpo.get("url")

            if not rawUrl:
                log.debug("Endpoint missing URL, skipping: %s", endpo)
                return []

            params = endpo.get("params", [])
            fullUrl = rawUrl if rawUrl.startswith("http") else urljoin(base, rawUrl)

            if self.run_paths:

                # Path traversal fuzzing
                ctx.runtime.util.status(f"[Thread] Path Fuzzing: {fullUrl}")
                bail = threading.Event() if args.bail_on_hit else None

                path_fuzzer = ctx.runtime.fuzz.create(
                    "path",
                    baseUrl=fullUrl,
                    wordlistPath= self.wordlistPathsParams,
                    session=sess,
                    auth=False,
                    bailEvent=bail,
                    ctx=ctx.runtime
                )
                setattr(path_fuzzer, "visitedPaths", ctx.shared["globalVisitedPaths"])
                setattr(path_fuzzer, "visitedFuzzPaths", ctx.shared["globalVisitedFuzzPaths"])
                setattr(path_fuzzer, "lock", ctx.shared["globalVisitedLock"])

                for path in ctx.runtime.util.get_parents(urlparse(fullUrl).path):
                    path_fuzzer.run(path=path)

                vulnerablePaths = getattr(path_fuzzer, "vulnerablePaths", {})
                if vulnerablePaths:
                    results.extend(list(vulnerablePaths.values()))
                if args.report_all:
                    interesting200 = getattr(path_fuzzer, "interesting200", None)
                    if interesting200: results.extend(interesting200)
                    interesting = getattr(path_fuzzer, "interesting", None)
                    if interesting: results.extend(interesting)

            if self.run_params and params:

                # Param fuzzing
                fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                ctx.runtime.util.status(f"[Thread] Param Fuzzing: {fuzzedUrl}")
                bail = threading.Event() if args.bail_on_hit else None

                param_fuzzer = ctx.runtime.fuzz.create(
                    "param",
                    baseUrl=fuzzedUrl,
                    wordlistPath=self.wordlistPathsParams,
                    session=sess,
                    auth=False,
                    bailEvent=bail,
                    ctx=ctx.runtime
                )

                res = param_fuzzer.run()
                if res:
                    results.extend(res)

            if self.run_xss_params and params:
                runToken = f"XSSCanary-{uuid4().hex[:8]}"

                # XSS fuzzing via params
                fuzzQuery = "&".join([f"{p}=FUZZ" for p in params])
                fuzzedUrl = f"{fullUrl}?{fuzzQuery}" if "?" not in fullUrl else f"{fullUrl}&{fuzzQuery}"

                ctx.runtime.util.status(f"[Thread] XSS Param Fuzzing: {fuzzedUrl}")
                bail = threading.Event() if args.bail_on_hit else None

                xss_param_fuzzer = ctx.runtime.fuzz.create(
                    "xss_param",
                    baseUrl=fuzzedUrl,
                    wordlistPath=self.wordlistXss,
                    session=sess,
                    auth=False,
                    token=runToken,
                    bailEvent=bail,
                    ctx=ctx.runtime
                )

                res = xss_param_fuzzer.run()

                if res:
                    results.extend(res)

            return results

        ctx.runtime.util.status(f"\n[+] Starting threaded fuzzing on discovered endpoints... \n")
        sessPool = []
        try:
            sessPool = ctx.runtime.auth.build_sessions(args.auth, args.username, args.password, args.start_url, args.login_path,
                                     desired_tasks=len(endpoints),
                                     threads_per_sess=cfg["concurrency"]["threads_per_session"],
                                     max_sess=cfg["concurrency"].get("max_sessions_cap", None),
                                     pool_headroom=0.25
                                     )
            log.debug("Session pool size=%d (phase=endpoints)", len(sessPool))
        except Exception:
            log.debug("Session pool build failed", exc_info=True)

        try:
            with ThreadPoolExecutor(max_workers=min(len(endpoints), cfg["concurrency"]["max_workers"])) as executor:
                # Run fuzzer using threads across all endpoints assigning a session from the session pool
                futures = []
                for i, epo in enumerate(endpoints):
                    sess = sessPool[i % len(sessPool)] if sessPool else None
                    futures.append(executor.submit(fuzzEndpoint, epo, sess))

                for future in as_completed(futures):
                    try:
                        resu = future.result()
                    except Exception:
                        log.debug("Endpoint future failed", exc_info=True)
                        continue
                    if resu:
                        allVulns.extend(resu)
        # Close sessions and delete the pool
        finally:
            if sessPool:
                for sess in sessPool:
                    try:
                        sess.close()
                    except Exception:
                        log.debug("Session close failed", exc_info=True)
                del sessPool

        return allVulns