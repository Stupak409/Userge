from userge import userge, Message, filters
import os, requests, json

app = userge.getLogger(__name__)
CHANNEL = userge.getCLogger(__name__)

# this module was developed by NKTKLN	
# https://t.me/NKTKLN

@userge.on_cmd("vt", about="VirusTotal scan")
async def vt_cmd(message: Message):
    try:
        for i in os.listdir("downloads"):
            os.system(f"rm -rf {i}")
    except:
        pass
    await message.edit("<b>Download...</b>")
    await message.reply_to_message.download()
    try:
        for i in os.listdir("downloads"):
            fil = "downloads/" + i
    except:
        await message.edit("<b>You did not select the file.</b>")
        return
    await message.edit("<b>Scan...</b>") 
    if fil.split(".")[-1] not in ["jpg", "png", "ico", "mp3", "mp4", "gif", "txt"]: 
        token = "d0c9094b17cb32063499738588fa39a500b829b5ef21944a0f621898773d8900"
        params = dict(apikey = token)
        with open(fil, 'rb') as file:
            files = dict(file=(fil, file))
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        os.system(f"rm -rf {fil}")
        try:
            if response.status_code == 200:
                false = []
                true = []
                result=response.json()
                res = (json.dumps(result, sort_keys=False, indent=4)).split()[10].split('"')[1]
                params = dict(apikey = token, resource=res)
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                if response.status_code == 200:
                    result = response.json()
                    print(result)
                    for key in result['scans']:
                        if result['scans'][key]['detected']:
                            false.append(f'⛔️ {key}')
                        else:
                            true.append(f'✅ {key}')
                await message.edit(f"🧬 Detections: {len(false)} / {len(result['scans'])}\n" + '\n'.join(false)+ "\n" + '\n'.join(true) + "\n\n" + f'''⚜️<a href="https://www.virustotal.com/gui/file/{result['resource']}/detection">Link to VirusTotal</a>''')
        except:
            await message.edit("<b>Scan Error.</b>")
    else:
        await message.edit("<b>This format is not supported.</b>")
        os.system(f"rm -rf {fil}")

app.run()