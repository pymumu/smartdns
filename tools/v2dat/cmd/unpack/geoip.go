package unpack

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/urlesistiana/v2dat/v2data"
	"go.uber.org/zap"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

func newGeoIPCmd() *cobra.Command {
	args := new(unpackArgs)
	c := &cobra.Command{
		Use:   "geoip [-o output_dir] [-f tag]... geoip.dat",
		Args:  cobra.ExactArgs(1),
		Short: "Unpack geoip file to text files.",
		Run: func(cmd *cobra.Command, a []string) {
			args.file = a[0]
			if err := unpackGeoIP(args); err != nil {
				logger.Fatal("failed to unpack geoip", zap.Error(err))
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVarP(&args.outDir, "out", "o", "", "output dir")
	c.Flags().StringArrayVarP(&args.filters, "filter", "f", nil, "unpack given tag")
	return c
}

func unpackGeoIP(args *unpackArgs) error {
	filePath, wantTags, ourDir := args.file, args.filters, args.outDir
	b, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	geoIPList, err := v2data.LoadGeoIPListFromDAT(b)
	if err != nil {
		return err
	}

	entries := make(map[string]*v2data.GeoIP)
	var wantEntries map[string]*v2data.GeoIP
	for _, geoSite := range geoIPList.GetEntry() {
		tag := strings.ToLower(geoSite.GetCountryCode())
		entries[tag] = geoSite
	}

	if len(wantTags) > 0 {
		wantEntries = make(map[string]*v2data.GeoIP)
		for _, tag := range wantTags {
			entry, ok := entries[tag]
			if !ok {
				return fmt.Errorf("cannot find entry %s", tag)
			}
			wantEntries[tag] = entry
		}
	} else {
		wantEntries = entries
	}

	for tag, ipList := range wantEntries {
		file := fmt.Sprintf("%s_%s.txt", fileName(filePath), tag)
		if len(ourDir) > 0 {
			file = filepath.Join(ourDir, file)
		}
		logger.Info(
			"unpacking entry",
			zap.String("tag", tag),
			zap.Int("length", len(ipList.GetCidr())),
			zap.String("file", file),
		)
		err := convertV2CidrToTextFile(ipList.GetCidr(), file)
		if err != nil {
			return err
		}
	}

	return nil
}

func convertV2CidrToTextFile(cidr []*v2data.CIDR, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	return convertV2CidrToText(cidr, f)
}

func convertV2CidrToText(cidr []*v2data.CIDR, w io.Writer) error {
	bw := bufio.NewWriter(w)
	for i, record := range cidr {
		ip, ok := netip.AddrFromSlice(record.Ip)
		if !ok {
			return fmt.Errorf("invalid ip at index #%d, %s", i, record.Ip)
		}
		prefix, err := ip.Prefix(int(record.Prefix))
		if !ok {
			return fmt.Errorf("invalid prefix at index #%d, %w", i, err)
		}

		if _, err := bw.WriteString(prefix.String()); err != nil {
			return err
		}
		if _, err := bw.WriteRune('\n'); err != nil {
			return err
		}
	}
	return bw.Flush()
}
