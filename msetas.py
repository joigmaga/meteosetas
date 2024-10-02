import shapely
import pandas as pd
import geopandas as gpd
import folium
from geojson2vt.geojson2vt import geojson2vt
from geojson2vt.vt2geojson import vt2geojson
import logging
import json
from util.jlatin import jlatin

#
# AEMET
#
AEMET_API_DIR = "/Users/igmartin/aemet/api"

ESTACIONES_AUTOMATICAS    = "/automaticas/Estaciones_Automaticas.shp"
ESTACIONES_PLUVIOMETRICAS = "/pluviometricas/Estaciones_Pluviometricas.shp"
INVENTARIO_ESTACIONES = (
      "/valores-climatologicos-inventarioestaciones-todasestaciones.json")

JSON_STATION_ID_LABEL = 'indicativo'
GPD_STATION_ID_LABEL  = 'INDICATIVO'

# IGN and Mapa Forestal
#
IGN_API_DIR = "/Users/igmartin/mapas"
MFE25_CANTABRIA = "/mfe/mfe_Cantabria/mfe_cantabria.shp"
MFE50_CANTABRIA = "/mfe/MFE50_39_tcm30-200066/mfe50_39.shp"

IGN_CARTO_NAME = "Cartografía Ráster de España del IGN"
IGN_CARTO_TILES = (
     "https://tms-mapa-raster.ign.es/1.0.0/mapa-raster/{z}/{x}/{-y}.jpeg")
IGN_CARTO_ATTRIBUTION = "<a href='https://www.ign.es/'>CC BY 4.0 ign.es</a>"
IGN_CARTO_MAXZOOM = 18

IGN_ORTO_NAME = "Mapa base de España ortofotos"
IGN_ORTO_TILES = (
     "https://tms-ign-base.idee.es/1.0.0/IGNBaseOrto/{z}/{x}/{-y}.png")
IGN_ORTO_ATTRIBUTION = "<a href='https://www.scne.es/'>CC BY 4.0 scne.es</a>"
IGN_ORTO_MAXZOOM = 17

IGN_SIMP_NAME = "Mapa base de España simplificado"
IGN_SIMP_TILES = (
     "https://tms-ign-base.idee.es/1.0.0/IGNBaseSimplificado/{z}/{x}/{-y}.png")
IGN_SIMP_ATTRIBUTION = "<a href='https://www.scne.es/'>CC BY 4.0 scne.es</a>"
IGN_SIMP_MAXZOOM = 17

IGN_BASE_NAME = "Mapa base de España"
IGN_BASE_TILES = (
     "https://tms-ign-base.idee.es/1.0.0/IGNBaseTodo/{z}/{x}/{-y}.jpeg")
IGN_BASE_ATTRIBUTION = "<a href='https://www.scne.es/'>CC BY 4.0 scne.es</a>"
IGN_BASE_MAXZOOM = 18

IGN_PNOA_NAME = "Ortofotos del PNOA"
IGN_PNOA_TILES = (
     "https://tms-pnoa-ma.idee.es/1.0.0/pnoa-ma/{z}/{x}/{-y}.jpeg")
IGN_PNOA_ATTRIBUTION = "<a href='https://www.scne.es/'>CC BY 4.0 scne.es</a>"
IGN_PNOA_MAXZOOM = 19

# CRS
#
GEO_CRS     = "EPSG:4258"
PROJECT_CRS = "EPSG:25830"

# OpenStreetMap
#
OSM_NAME  = "OpenStreetMap"
OSM_TILES = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
OSM_ATTRIBUTION = '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
OSM_MAXZOOM = 19

#
HTML_OUTPUT_MAP  = "/Users/igmartin/mapas/folium.html"
HTML_OUTPUT_MAP2 = "/Users/igmartin/mapas/folium-2.html"

###############
# read shapefiles containing meteorological data
#
def read_meteodata():

    auto_data   = gpd.read_file(AEMET_API_DIR + ESTACIONES_AUTOMATICAS)
    pluvio_data = gpd.read_file(AEMET_API_DIR + ESTACIONES_PLUVIOMETRICAS)

    # join the two GeoDataFrames into one
    ap_data = pd.concat([auto_data, pluvio_data], ignore_index=True)

    # AEMET json data is encoded with ISO latin characters. Use ISO-8859-15
    # charset encoding for converting to UTF-8 Unicode, as requiresd by Python
    #

    # read the meteo station inventory and bild a list of valid stations
    #
    inv = jlatin(AEMET_API_DIR + INVENTARIO_ESTACIONES)
    linv = [x[JSON_STATION_ID_LABEL] for x in inv]

    # build a GeoSeries object with the valid station names
    #
    ap_data_gsinv = ap_data[GPD_STATION_ID_LABEL].isin(linv)

    # build a list of non-conformant stations and remove them from the GDF
    #
    dellist = list(ap_data_gsinv.index[ap_data_gsinv == False])
    ap_data = ap_data.drop(ap_data.index[dellist])

    # and reset the index of the GDP
    #
    ap_data.reset_index(drop=True, inplace=True)

    return ap_data

###############
# CRS
###############

def set_projection(geodata, proj_crs=PROJECT_CRS):

    # project geographic data in UTM Zone 30 (Central Spain)

    return geodata.to_crs(proj_crs)

###############################
# This is calculated everytime a click is made on the map
###############################
# setting distance in meters
#

def set_distance(geodata, point, crs=GEO_CRS):

    # build a GeoDataFrame with a single point
    #
    gdf = gpd.GeoDataFrame({'geometry': [point]}, crs=crs)

    # Project coordinates into UTMP zone 30
    #
    gdf.to_crs("EPSG:25830", inplace=True)

    # finally, recalculate all the distances using the new geometry
    #
    geodata.loc[:, 'DISTANCIA'] = geodata.distance(gdf.geometry[0], align=True)

    return geodata

def closer_than(geodata, dist):

    return geodata[ap_data['DISTANCIA'] < dist].sort_values(by='DISTANCIA')

############################################3
#
# MFE

mfe_columns = ['superficie', 'form_arb_d',    'tipobosque',     'especie1']
mfe_aliases = ['Hectáreas', ' Forma arbórea', 'Tipo de bosque', 'Especies']

def read_terrain():

    mfe_data = gpd.read_file(IGN_API_DIR + MFE25_CANTABRIA)

    # remove all rows whit soil type not matching 'forest'
    #
    mfe_data = mfe_data[mfe_data['form_arb_d'] != 'No arbolado']
    mfe_data.reset_index(drop=True, inplace=True)

    # Pack and remove all the 'species' information into one single column 
    #
    for row in mfe_data.index:
        mfe_data.loc[row, 'especie1'] += (" (%s%%) %s" % (
               mfe_data.loc[row, 'o1'],
               mfe_data.loc[row, 'estado1']))
        if mfe_data.loc[row, 'especie2'] == "sin datos":
            continue
        mfe_data.loc[row, 'especie1'] += (", %s (%s%%) %s" % ( 
               mfe_data.loc[row, 'especie2'], 
               mfe_data.loc[row, 'o2'],
               mfe_data.loc[row, 'estado2'])) 
        if mfe_data.loc[row, 'especie3'] == "sin datos":
            continue
        mfe_data.loc[row, 'especie1'] += (", %s (%s%%) %s" % ( 
               mfe_data.loc[row, 'especie3'], 
               mfe_data.loc[row, 'o3'],
               mfe_data.loc[row, 'estado3'])) 

    mfe_notused = [x for x in list(mfe_data.columns)
                  if x not in mfe_columns + ['geometry']]
    mfe_data.drop(columns=mfe_notused, inplace=True)

    return mfe_data

def optimize(data):

    data = json.loads(data.to_json())
    
    # build an initial index of tiles
    tile_index = geojson2vt(data, {
	'maxZoom': 14,  # max zoom to preserve detail on; can't be higher than 24
	'tolerance': 3, # simplification tolerance (higher means simpler)
	'extent': 4096, # tile extent (both width and height)
	'buffer': 64,   # tile buffer on each side
	'lineMetrics': False, # whether to enable line metrics tracking for LineString/MultiLineString features
	'promoteId': None,    # name of a feature property to promote to feature.id. Cannot be used with `generateId`
	'generateId': False,  # whether to generate feature ids. Cannot be used with `promoteId`
	'indexMaxZoom': 5,       # max zoom in the initial tile index
	'indexMaxPoints': 25000 # max number of points per tile in the index
    }, logging.DEBUG)

    for coord in tile_index.tile_coords:
        z, x, y = tuple(coord.values())
        vector_tile = tile_index.get_tile(z, x, y)
        geojson = vt2geojson(vector_tile)                     
        with open(
          '/Users/igmartin/mapas/geotiles/map-%s-%s-%s.json' % (z, x, y), "w") as f:
            f.write(str(geojson))

#############################################
#
# The folium stuff

def create_map(ap_data, mfe_data, central_point):

    meteo_fields = ["INDICATIVO", "NOMBRE", "PROVINCIA"]

    carto = folium.TileLayer(tiles=IGN_CARTO_TILES,
                             attr=IGN_CARTO_ATTRIBUTION,
                             name=IGN_CARTO_NAME,
                             max_zoom=IGN_CARTO_MAXZOOM,
                             overlay=False, control=True, show=True)
    base  = folium.TileLayer(tiles=IGN_BASE_TILES,
                             attr=IGN_BASE_ATTRIBUTION,
                             name=IGN_BASE_NAME,
                             max_zoom=IGN_BASE_MAXZOOM,
                             overlay=False, control=True, show=False)
    pnoa  = folium.TileLayer(tiles=IGN_PNOA_TILES,
                             attr=IGN_PNOA_ATTRIBUTION,
                             name=IGN_PNOA_NAME,
                             max_zoom=IGN_PNOA_MAXZOOM,
                             overlay=False, control=True, show=False)
    osm   = folium.TileLayer(tiles=OSM_TILES,
                             attr=OSM_ATTRIBUTION,
                             name=OSM_NAME,
                             max_zoom=OSM_MAXZOOM,
                             overlay=False, control=True, show=False)

    # create base map with default map selected
    #
    m = folium.Map(location=(central_point.y, central_point.x),
                   tiles=carto, zoom_start=10)

    # add more maps to the base layer
    #
    base.add_to(m)
    pnoa.add_to(m)
    osm.add_to(m)

#        url="https://wms.mapama.gob.es/sig/Biodiversidad/MFE/wmts.aspx?"
#        layers="LC.LandCoverSurfaces",
#        styles="LC.LandCoverSurfaces.Default",
#
#        url="https://wmts.mapama.gob.es/sig/biodiversidad/gwc/service/wmts?"
#            "request=getcapabilities&service=wmts",
#        layers="Mapa Forestal de España de máxima actualidad",
#
#    folium.WmsTileLayer(
#        url="https://wms.mapama.gob.es/sig/Biodiversidad/MFE/wmts.aspx?"
#            "request=getcapabilities&service=wms",
#        layers="LC.LandCoverSurfaces",
#        styles="LC.LandCoverSurfaces.Default",
#        format="image/png",
#        attr="CC BY 4.0. "
#             "Ministerio para la Transición Ecológica y el Reto Demográfico",
#        name="Mapa Forestal de España",
#        transparent=False,
#        minZoom=16,
#        maxZoom=18,
#        overlay=False,
#        control=True,
#        show=True,
#       ).add_to(m)
    
    # add meteorological layer to map
    #
    folium.GeoJson(
        ap_data,
        name="Estaciones Meteorológicas AEMET",
        zoom_on_click=False,
        marker=folium.Marker(icon=folium.Icon()),
        tooltip=folium.GeoJsonTooltip(fields=meteo_fields),
        control=True,
        show=False,
       ).add_to(m)
 
    # add MFE layer
    #
    folium.GeoJson(
        mfe_data,
        name="Mapa Forestal de España",
        stroke=True,
        color="black",
        weight=1,
        opacity=1,
        highlight_function=lambda x: { "fillColor": "green" },
        fill=True,
        fill_color="lightgreen",
        fill_opacity=0.2,
        highlight=True,
        popup=folium.GeoJsonPopup(fields=mfe_columns, aliases=mfe_aliases),
        overlay=True,
        control=True,
        show=False,
       ).add_to(m)

    # add control box to switch on/off layers
    #
    folium.LayerControl().add_to(m)

    # finally, save the map to HTML
    #
    m.save(HTML_OUTPUT_MAP)

    return m

##########################################

Nestares = shapely.Point(-4.160594, 42.991882)

ap_data = read_meteodata()
ap_data = set_projection(ap_data, PROJECT_CRS)
ap_data = set_distance(ap_data, Nestares)
mfe_data = read_terrain()
#optimize(mfe_data)
m = create_map(ap_data, mfe_data, Nestares)

##########################################

# p = shapely.Point(-3.5, 42.1)
# p
# <POINT (-3.5 42.1)>
#
# import math
# def distance_meters(lat1, lon1, lat2, lon2):
#     latMid  = (lat1 + lat2)/2.0
#     deltaLat = abs(lat1 - lat2)
#     deltaLon = abs(lon1 - lon2)
#     m_per_deg_lat = 111132.954 - 559.822*math.cos(2*math.radians(latMid)) + 1.175*math.cos(4*math.radians(latMid)) - 0.0023*math.cos(6*math.radians(latMid))
#     m_per_deg_lon = 111412.84*math.cos(math.radians(latMid)) - 93.5*math.cos(3*math.radians(latMid)) + 0.118*math.cos(5*math.radians(latMid))
#     dist_m = math.sqrt((deltaLat*m_per_deg_lat)**2 + (deltaLon*m_per_deg_lon)**2)
#     return dist_m
#
##################################
# Note the difference between "Geographic CRS" (ETRS89, EPSG:4258) and
# "Projected CRS" (ETRS89 UTM, EPSG:25830), with units in meters
#
# We project over the zone 30N which covers central Spain
# 
# EPSG:25829 Western Spain 
# EPSG:25830 Central Spain
# EPSG:25831 Eastern Spain 
# EPSG:25828 Canary Islands                      # Note: uses WSG84 datum
# EPSG:25227 Little portion of El Hierro island  # Note: uses WSG84 datum
#
