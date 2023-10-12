package v2data

import "google.golang.org/protobuf/proto"

func LoadGeoSiteList(b []byte) (*GeoSiteList, error) {
	geoSiteList := new(GeoSiteList)
	if err := proto.Unmarshal(b, geoSiteList); err != nil {
		return nil, err
	}
	return geoSiteList, nil
}

func LoadGeoIPListFromDAT(b []byte) (*GeoIPList, error) {
	geoIP := new(GeoIPList)
	if err := proto.Unmarshal(b, geoIP); err != nil {
		return nil, err
	}
	return geoIP, nil
}
