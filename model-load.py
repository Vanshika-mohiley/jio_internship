import ollama as ola
from datasetloader import load_full_dataset
from runprompt import run_all
from ragretrival import build_corpus,RAG_MODELS
def getmodels():
    response=ola.list()
    return([m.model for m in response.models])

models=getmodels()
dataset=load_full_dataset(
    {
            "cve_known_csv": "category1_final.csv",
            "cve_novel_csv": "category2_final.csv",
            "os_config_index_csv": "os_config_index.csv",
            "os_config_base_dir": "category3snippets",
            "k8s_index_csv": "k8s_index.csv",
            "k8s_base_dir": "category4_manifest",
            "multi_artefact_dir": "category5_scenarios",
        }

)
rag_collection = build_corpus("category2_final.csv")

run_all(
    models=models,
    dataset=dataset,
    rag_models=RAG_MODELS,
    rag_collection=rag_collection,
    output_csv="evaluation_results.csv",
)

