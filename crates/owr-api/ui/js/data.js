/* data.js - static lookup data: IANA time zones (common subset) and Wi-Fi regulatory countries. */

export const ZONES = (
  'UTC Etc/GMT Europe/London Europe/Dublin Europe/Lisbon Europe/Paris Europe/Berlin Europe/Madrid ' +
  'Europe/Rome Europe/Amsterdam Europe/Brussels Europe/Zurich Europe/Vienna Europe/Prague Europe/Warsaw ' +
  'Europe/Stockholm Europe/Oslo Europe/Copenhagen Europe/Helsinki Europe/Athens Europe/Bucharest ' +
  'Europe/Kyiv Europe/Istanbul Europe/Moscow Africa/Casablanca Africa/Lagos Africa/Cairo Africa/Nairobi ' +
  'Africa/Johannesburg Asia/Jerusalem Asia/Riyadh Asia/Dubai Asia/Tehran Asia/Karachi Asia/Kolkata ' +
  'Asia/Dhaka Asia/Bangkok Asia/Jakarta Asia/Ho_Chi_Minh Asia/Singapore Asia/Kuala_Lumpur Asia/Manila ' +
  'Asia/Hong_Kong Asia/Shanghai Asia/Taipei Asia/Seoul Asia/Tokyo Australia/Perth Australia/Adelaide ' +
  'Australia/Brisbane Australia/Sydney Australia/Melbourne Pacific/Auckland Pacific/Fiji Pacific/Honolulu ' +
  'America/Anchorage America/Los_Angeles America/Vancouver America/Phoenix America/Denver America/Edmonton ' +
  'America/Chicago America/Winnipeg America/Mexico_City America/Guatemala America/Costa_Rica ' +
  'America/New_York America/Toronto America/Halifax America/St_Johns America/Havana America/Bogota ' +
  'America/Lima America/Caracas America/Santiago America/Sao_Paulo America/Argentina/Buenos_Aires ' +
  'America/Montevideo Atlantic/Reykjavik Atlantic/Azores Indian/Maldives'
).split(' ');

export const COUNTRIES = Object.fromEntries(
  (
    'US:United States,CA:Canada,MX:Mexico,GB:United Kingdom,IE:Ireland,DE:Germany,FR:France,ES:Spain,' +
    'PT:Portugal,IT:Italy,NL:Netherlands,BE:Belgium,LU:Luxembourg,CH:Switzerland,AT:Austria,CZ:Czechia,' +
    'PL:Poland,SE:Sweden,NO:Norway,DK:Denmark,FI:Finland,IS:Iceland,GR:Greece,RO:Romania,HU:Hungary,' +
    'BG:Bulgaria,HR:Croatia,SK:Slovakia,SI:Slovenia,EE:Estonia,LV:Latvia,LT:Lithuania,UA:Ukraine,TR:Turkiye,' +
    'IL:Israel,AE:United Arab Emirates,SA:Saudi Arabia,ZA:South Africa,EG:Egypt,NG:Nigeria,KE:Kenya,' +
    'IN:India,SG:Singapore,MY:Malaysia,TH:Thailand,ID:Indonesia,PH:Philippines,VN:Vietnam,HK:Hong Kong,' +
    'TW:Taiwan,KR:South Korea,JP:Japan,CN:China,AU:Australia,NZ:New Zealand,BR:Brazil,AR:Argentina,' +
    'CL:Chile,CO:Colombia,PE:Peru'
  ).split(',').map((s) => s.split(':')),
);
