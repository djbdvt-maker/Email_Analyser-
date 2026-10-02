import React, { useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix leaflet icon missing in react-leaflet
// @ts-ignore
import icon from 'leaflet/dist/images/marker-icon.png';
// @ts-ignore
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

const countryCoords: Record<string, [number, number]> = {
  "RU": [61.524, 105.3188],
  "US": [37.0902, -95.7129],
  "CN": [35.8617, 104.1954],
  "KP": [40.3399, 127.5101],
  "IR": [32.4279, 53.6880],
  "BY": [53.7098, 27.9534],
  "SY": [34.8021, 38.9968]
};

interface MapProps {
  locations: Array<{ ip: string, geo: string }>;
}

function MapUpdater({ center }: { center: [number, number] }) {
  const map = useMap();
  useEffect(() => {
    map.setView(center, 3);
  }, [center, map]);
  return null;
}

export const GeolocationMap: React.FC<MapProps> = ({ locations }) => {
  let center: [number, number] = [20, 0];
  const markers = [];

  for (const loc of locations) {
    if (!loc.geo) continue;
    
    // Extract ISO code from "Russia (RU)"
    const match = loc.geo.match(/\(([A-Z]{2})\)/);
    const iso = match ? match[1] : null;
    
    if (iso && countryCoords[iso]) {
      center = countryCoords[iso];
      markers.push({
        position: countryCoords[iso],
        ip: loc.ip,
        geo: loc.geo
      });
    }
  }

  return (
    <div style={{ height: '300px', width: '100%', borderRadius: '8px', overflow: 'hidden', marginTop: '1rem', border: '1px solid var(--border-color)' }}>
      <MapContainer center={center} zoom={2} scrollWheelZoom={false} style={{ height: '100%', width: '100%' }}>
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {markers.map((m, i) => (
          <Marker key={i} position={m.position}>
            <Popup>
              <strong>{m.ip}</strong><br/>
              {m.geo}
            </Popup>
          </Marker>
        ))}
        {markers.length > 0 && <MapUpdater center={center} />}
      </MapContainer>
    </div>
  );
};
