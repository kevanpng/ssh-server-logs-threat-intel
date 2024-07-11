from main import _extract_info
import json

def test_extract_info():
    #given
    with open('./example_virus_total_response.json', 'r') as f:
        test_virus_total_response = json.load(f)

    #when
    info = _extract_info(test_virus_total_response)
    #then
    assert info == {
         "value": "91.224.160.106",
         "type": "ip",
         "providers": [
            {
               "provider": "VirusTotal",
               "verdict": "harmless",
               "score": "63/63"
            }

         ]
      }, f'info does not match. info is {info}' #

if __name__ == '__main__':
    test_extract_info()