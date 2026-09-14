from src.preprocessing import load_data, extract_features
from src.detector import detect_anomalies, get_current_stage
from src.forecaster import forecast_next_stage
from src.mitre_mapper import map_to_mitre, ATTACK_CHAIN

df = load_data('data/sample_network_data.csv')
print(f'Loaded {len(df)} flows')

df = extract_features(df)
df = detect_anomalies(df)

current = get_current_stage(df)
mitre_now = map_to_mitre(current)

avg_threat = int(df['threat_score'].mean())
forecast = forecast_next_stage(current, avg_threat)
mitre_next = map_to_mitre(forecast['next_stage'])

print('=' * 60)
print('CURRENT STAGE:', current)
print('  MITRE ID:   ', mitre_now['technique_id'])
print('  Technique:  ', mitre_now['technique'])
print('  Risk:       ', mitre_now['risk'])
print('=' * 60)
print('FORECAST NEXT:', forecast['next_stage'])
print('  Confidence: ', forecast['confidence'], '%')
print('  MITRE ID:   ', mitre_next['technique_id'])
print('  Technique:  ', mitre_next['technique'])
print('  Risk:       ', mitre_next['risk'])
print('=' * 60)
print('ATTACK CHAIN:')
for i, stage in enumerate(ATTACK_CHAIN):
    marker = ''
    if stage == current:
        marker = '  <-- CURRENT'
    elif stage == forecast['next_stage'] and stage != current:
        marker = '  <-- FORECAST'
    print(f'  {i+1}. {stage}{marker}')
print('=' * 60)
