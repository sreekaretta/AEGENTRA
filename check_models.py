import google.generativeai as genai
import os

api_key = os.environ.get('GEMINI_API_KEY')
genai.configure(api_key=api_key)

print("Available Gemini models:")
print("=" * 50)

for model in genai.list_models():
    if 'generateContent' in model.supported_generation_methods:
        print(f"✅ {model.name}")
        print(f"   Display Name: {model.display_name}")
        print()
