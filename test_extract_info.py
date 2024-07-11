from test_extract_info import _extract_info
import json

def test_extract_info():
    #given
    with open('./example_virus_total_response.json', 'r') as f:
        test_virus_total_response = json.load(f)


    #when
    info = _extract_info(test_virus_total_response)
    #then
    assert info == {
         "value":"31.139.365.245",
         "type":"ip",
         "providers":[
            {
               "provider":"VirusTotal",
               "verdict":"harmless",
               "score": "5/5"
            }

         ]
      }, f'info does not match. info is {info}' #

if __name__ == '__main__':
    test_extract_info()