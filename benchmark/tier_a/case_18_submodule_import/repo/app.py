from geo_utils.coordinates import parse_lat_lon

def get_pos(s: str):
    return parse_lat_lon(s)
