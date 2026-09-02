import ollama as ola
import time
def getmodels():
    response=ola.list()
    return([m.model for m in response.models])
def run_prompt(model:str , prompt:str):
    print(f"\n{'='*60}")
    print(f"Model : {model}")
    print(f"{'='*60}")
    start = time.perf_counter()
    try:
        convo = ola.generate(model = model , prompt= prompt)
        elapsed = time.perf_counter() - start
        content= convo["response"]
        token = convo.get('eval_count',0)
        token_per_sec = token/elapsed if elapsed > 0 else 0

        print(content)
        print( f"\n --{elapsed : .2f}s   |  {token} tokens  | {token_per_sec : .1f} tok/s -- " )
    except Exception as e:
        print(f"{model} is not running")
models=getmodels()

prompt = input("Enter prompt : ")
for model in models:
    run_prompt(model , prompt)

