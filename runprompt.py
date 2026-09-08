import argparse
import csv
import os
import time
import ollama as ola
from datasetloader import load_full_dataset
from prompt_builder import build_prompt
VALID_CATEGORIES = {"cve_known", "cve_novel", "os_config", "k8s_manifest", "multi_artefact"}
def run_single(model: str, prompt: str) -> dict:
    """Calls Ollama once and returns timing/content info. Never raises."""
    start = time.perf_counter()
    try:
        convo = ola.generate(
            model=model,
            prompt=prompt,
            keep_alive="30m",                     
            options={"num_predict": 800},          
        )
        elapsed = time.perf_counter() - start
        content = convo["response"]
        tokens = convo.get("eval_count", 0)
        tok_per_sec = tokens / elapsed if elapsed > 0 else 0
        return {
            "ok": True,
            "response": content,
            "elapsed": elapsed,
            "tokens": tokens,
            "tok_per_sec": tok_per_sec,
            "error": "",
        }
    except Exception as e:
        elapsed = time.perf_counter() - start
        return {
            "ok": False,
            "response": "",
            "elapsed": elapsed,
            "tokens": 0,
            "tok_per_sec": 0,
            "error": str(e),
        }


def _load_completed_keys(output_csv: str) -> set:
    """
    Returns a set of (item_id, model) pairs that already have a successful
    (ok=True) row in output_csv.
    """
    completed = set()
    if not os.path.isfile(output_csv):
        return completed
    with open(output_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("ok") in ("True", "true", True):
                completed.add((row.get("item_id"), row.get("model")))
    return completed


def run_category(model: str, category: str, dataset: list, output_csv: str = None,
                  verbose: bool = True, resume: bool = True, model_label: str = None):
    items = dataset if category == "all" else [i for i in dataset if i.get("category") == category]

    if model_label is None:
        model_label = model
 
    if output_csv is None:
        output_csv = f"eval_{model}_{category}.csv"

    completed = _load_completed_keys(output_csv) if resume else set()
    if completed:
        before = len(items)
        items = [i for i in items if (i.get("id"), model_label) not in completed]
        skipped = before - len(items)
        if skipped:
            print(f"Resuming: skipping {skipped} already-completed item(s) for model='{model_label}'.")

    if not items:
        print(f"All items for model='{model_label}', category='{category}' already completed. Nothing to run.")
        return []

    file_exists = os.path.isfile(output_csv)
    results = []

    with open(output_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["item_id", "category", "model", "prompt", "response",
                              "latency_s", "tokens", "tok_per_sec", "ok", "error"])

        for item in items:
            prompt = build_prompt(item)

            if verbose:
                print(f"\n{'='*60}")
                print(f"Model: {model_label}  |  Item: {item.get('id')}  ({item.get('category')})")
                print(f"{'='*60}")

            result = run_single(model, prompt)

            if verbose:
                if result["ok"]:
                    print(result["response"])
                    print(f"\n --{result['elapsed']:.2f}s | {result['tokens']} tokens "
                          f"| {result['tok_per_sec']:.1f} tok/s --")
                else:
                    print(f"{model_label} failed on {item.get('id')}: {result['error']}")

            writer.writerow([
                item.get("id"), item.get("category"), model_label, prompt,
                result["response"], f"{result['elapsed']:.3f}",
                result["tokens"], f"{result['tok_per_sec']:.1f}",
                result["ok"], result["error"],
            ])
            # Flush immediately so progress is saved to disk even if the
            # process is killed mid-run (Ctrl+C, laptop sleep, crash, etc.)
            f.flush()
            results.append({**item, **result})

    print(f"\nDone. {len(items)} items processed for model='{model_label}', category='{category}'. "
          f"Results appended to {output_csv}")
    return results


def run_all(models: list, dataset: list, categories: list = None,
            rag_models: set = None, rag_collection=None,
            output_csv: str = "evaluation_results.csv"):
    """
    Runs EVERY model against EVERY category, one combination at a time,
    all appended into a single CSV (matching the Day 2-3 spec: 100 items
    x 6 models = 700+ rows
    """
    if categories is None:
        categories = sorted(VALID_CATEGORIES)
    if rag_models is None:
        rag_models = set()

    for model in models:
        for category in categories:
            print(f"\n\n### Running model='{model}' on category='{category}' ###")

            if category == "cve_novel" and model in rag_models:
                print(">>> RAG BRANCH ENTERED <<<")
                if rag_collection is None:
                    raise ValueError(
                        f"'{model}' is listed in rag_models but no rag_collection was provided."
                    )
                # Lazy import so this file works even if rag_retrieval / chromadb
                # aren't installed for people who aren't using RAG at all.
                from ragretrival import retrieve_context

                novel_items = [i for i in dataset if i.get("category") == "cve_novel"]
                rag_items = []
                for item in novel_items:
                    item_with_context = dict(item)
                    item_with_context["retrieved_context"] = retrieve_context(rag_collection, item)
                    rag_items.append(item_with_context)

                # Run once WITHOUT context (base behaviour) ...
                base_items = [dict(i, retrieved_context="") for i in novel_items]
                run_category(model=model, category="cve_novel", dataset=base_items,
                              output_csv=output_csv)
                # ... and once WITH retrieved context, so you get the base-vs-RAG
                # delta this model/category pair is specifically meant to produce.
                run_category(model=model, model_label=f"{model}+rag",category="cve_novel", dataset=rag_items,
                              output_csv=output_csv)
            else:
                print(f">>> RAG BRANCH SKIPPED (category={category!r}, model={model!r}, rag_models={rag_models!r})")
                run_category(model=model, category=category, dataset=dataset,output_csv=output_csv)

    print(f"\n\nAll models x all categories complete. Full log: {output_csv}")


def _cli():
    parser = argparse.ArgumentParser(description="Run model(s) against dataset categories.")
    parser.add_argument("--model", default=None,
                         help="Single Ollama model name, e.g. llama3.1. Omit this and use --all-models instead to sweep every installed model.")
    parser.add_argument("--all-models", action="store_true",
                         help="Run every model returned by `ollama list`, instead of a single --model.")
    parser.add_argument("--category", default="all",
                         choices=list(VALID_CATEGORIES) + ["all"],
                         help="Dataset category to run, or 'all' for everything (default: all)")
    parser.add_argument("--output", default="evaluation_results.csv",
                         help="Output CSV path (default: evaluation_results.csv)")
    args = parser.parse_args()

    dataset = load_full_dataset({
        "cve_known_csv": "category1_final.csv",
        "cve_novel_csv": "category2_final.csv",
        "os_config_index_csv": "os_config_index.csv",
        "os_config_base_dir": "category3snippets",
        "k8s_index_csv": "k8s_index.csv",
        "k8s_base_dir": "category4_manifest",
        "multi_artefact_dir": "category5_scenarios",
    })

    if args.all_models:
        response = ola.list()
        models = [m.model for m in response.models]
        categories = list(VALID_CATEGORIES) if args.category == "all" else [args.category]
        run_all(models=models, dataset=dataset, categories=categories, output_csv=args.output)
    else:
        if not args.model:
            parser.error("Provide --model <name>, or use --all-models to sweep every installed model.")
        run_category(model=args.model, category=args.category, dataset=dataset, output_csv=args.output)
