package jar

import (
	"archive/zip"
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

const ()

var (
	jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)
)

type Client interface {
	Exists(groupID, artifactID string) (bool, error)
	SearchBySHA1(sha1 string) (Properties, error)
	SearchByArtifactID(artifactID string) (string, error)
}

type Parser struct {
	rootFilePath string
	offline      bool
	size         int64

	client Client
}

type Option func(*Parser)

func WithFilePath(filePath string) Option {
	return func(p *Parser) {
		p.rootFilePath = filePath
	}
}

func WithOffline(offline bool) Option {
	return func(p *Parser) {
		p.offline = offline
	}
}

func WithSize(size int64) Option {
	return func(p *Parser) {
		p.size = size
	}
}

func NewParser(c Client, opts ...Option) types.Parser {
	p := &Parser{
		client: c,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	return p.parseArtifact(p.rootFilePath, p.size, r)
}

func (p *Parser) parseArtifact(fileName string, size int64, r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	log.Logger.Debugw("JJW Parsing Java artifacts...", zap.String("file", fileName))

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileName = filepath.Base(fileName)
	fileProps := parseFileName(fileName)

	var libs []types.Library
	var m manifest
	var foundPomProps bool
	var props Properties
	var manifestProps Properties
	var license string
	var err error

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, nil, xerrors.Errorf("zip error: %w", err)
	}

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err = parsePomProperties(fileInJar)
			log.Logger.Debugf("Found in POM: %#v", props)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			// Check if the pom.properties is for the original JAR/WAR/EAR
			if fileProps.ArtifactID == props.ArtifactID && fileProps.Version == props.Version {
				foundPomProps = true
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to parse MANIFEST.MF: %w", err)
			}
		case strings.Contains(strings.ToLower(filepath.Base(fileInJar.Name)), "license"):
			//TODO: add license file processing
			log.Logger.Debugf("license file found")
			license = ""
		case isArtifact(fileInJar.Name):
			innerLibs, _, err := p.parseInnerJar(fileInJar) //TODO process inner deps
			if err != nil {
				log.Logger.Debugf("Failed to parse %s: %s", fileInJar.Name, err)
				continue
			}
			libs = append(libs, innerLibs...)
		}
	}
	manifestProps = m.properties()
	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	// Check for completeness and supplement it from manifest or license file
	// If we found license in the pom.properties return
	if foundPomProps {
		switch {
		case props.License != "":
			log.Logger.Debugf("License found in POM: %#v", props)
		case manifestProps.License != "":
			props.License = manifestProps.License
			log.Logger.Debugf("License found in the manifest: %#v", props)
		case license != "":
			props.License = manifestProps.License
			log.Logger.Debugf("License found in the license file: %#v", props)
		}
		libs = append(libs, props.Library())
		return libs, nil, nil
	}

	// We continue here with the original  logic
	// TODO: when JavaDB is expanded to store licenses, one extra
	// case should be added to the switch above

	if p.offline || true {
		// In offline mode, we will not check if the artifact information is correct.
		if !manifestProps.Valid() {
			log.Logger.Debugw("Unable to identify POM in offline mode", zap.String("file", fileName))
			return libs, nil, nil
		}
		return append(libs, manifestProps.Library()), nil, nil
	}

	if manifestProps.Valid() {
		// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
		// We have to make sure that the artifact exists actually.
		if ok, _ := p.client.Exists(manifestProps.GroupID, manifestProps.ArtifactID); ok {
			// If groupId and artifactId are valid, they will be returned.
			return append(libs, manifestProps.Library()), nil, nil
		}
	}

	log.Logger.Debugf("Calling maven central: %#v", manifestProps)
	// If groupId and artifactId are not found, call Maven Central's search API with SHA-1 digest.
	props, err = p.searchBySHA1(r)
	if err == nil {
		return append(libs, props.Library()), nil, nil
	} else if !xerrors.Is(err, ArtifactNotFoundErr) {
		return nil, nil, xerrors.Errorf("failed to search by SHA1: %w", err)
	}

	log.Logger.Debugw("No such POM in the central repositories", zap.String("file", fileName))

	// Return when artifactId or version from the file name are empty
	if fileProps.ArtifactID == "" || fileProps.Version == "" {
		return libs, nil, nil
	}

	// Try to search groupId by artifactId via sonatype API
	// When some artifacts have the same groupIds, it might result in false detection.
	fileProps.GroupID, err = p.client.SearchByArtifactID(fileProps.ArtifactID)
	if err == nil {
		log.Logger.Debugw("POM was determined in a heuristic way", zap.String("file", fileName),
			zap.String("artifact", fileProps.String()))
		libs = append(libs, fileProps.Library())
	} else if !xerrors.Is(err, ArtifactNotFoundErr) {
		return nil, nil, xerrors.Errorf("failed to search by artifact id: %w", err)
	}

	return libs, nil, nil
}

func (p *Parser) parseInnerJar(zf *zip.File) ([]types.Library, []types.Dependency, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to open %s: %w", zf.Name, err)
	}

	f, err := os.CreateTemp("", "inner")
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to create a temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	// Copy the file content to the temp file
	if _, err = io.Copy(f, fr); err != nil {
		return nil, nil, xerrors.Errorf("file copy error: %w", err)
	}

	// Parse jar/war/ear recursively
	innerLibs, innerDeps, err := p.parseArtifact(zf.Name, int64(zf.UncompressedSize64), f)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse %s: %w", zf.Name, err)
	}

	return innerLibs, innerDeps, nil
}

func (p *Parser) searchBySHA1(r io.ReadSeeker) (Properties, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return Properties{}, xerrors.Errorf("file seek error: %w", err)
	}

	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return Properties{}, xerrors.Errorf("unable to calculate SHA-1: %w", err)
	}
	s := hex.EncodeToString(h.Sum(nil))
	prop, err := p.client.SearchBySHA1(s)
	if err != nil {
		return Properties{}, err
	}
	return prop, nil
}

func isArtifact(name string) bool {
	ext := filepath.Ext(name)
	if ext == ".jar" || ext == ".ear" || ext == ".war" {
		return true
	}
	return false
}

func parseFileName(fileName string) Properties {
	packageVersion := jarFileRegEx.FindStringSubmatch(fileName)
	if len(packageVersion) != 3 {
		return Properties{}
	}

	return Properties{
		ArtifactID: packageVersion[1],
		Version:    packageVersion[2],
	}
}

func parsePomProperties(f *zip.File) (Properties, error) {
	file, err := f.Open()
	if err != nil {
		return Properties{}, xerrors.Errorf("unable to open pom.properties: %w", err)
	}
	defer file.Close()

	var p Properties
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.GroupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.ArtifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.Version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return Properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return p, nil
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendor   string
	implementationVendorId string
	specificationTitle     string
	specificationVersion   string
	specificationVendor    string
	bundleName             string
	bundleVersion          string
	bundleSymbolicName     string
	bundleLicense          string
}

func parseManifest(f *zip.File) (manifest, error) {
	file, err := f.Open()
	if err != nil {
		return manifest{}, xerrors.Errorf("unable to open MANIFEST.MF: %w", err)
	}
	defer file.Close()

	var m manifest
	scanner := bufio.NewScanner(file)
	var manifestField string
	for scanner.Scan() {
		line := scanner.Text()
		// JAR Maifest lines are limited to 72 characters,
		// content continues in new line that start wihh a single space
		if strings.HasPrefix(line, " ") {
			manifestField += strings.TrimSpace(line)
		} else {
			manifestField = line
		}
		// Skip variables. e.g. Bundle-Name: %bundleName
		ss := strings.Fields(manifestField)
		if len(ss) <= 1 || (len(ss) > 1 && strings.HasPrefix(ss[1], "%")) {
			continue
		}

		// It is not determined which fields are present in each application.
		// In some cases, none of them are included, in which case they cannot be detected.
		switch {
		case strings.HasPrefix(manifestField, "Implementation-Version:"):
			m.implementationVersion = strings.TrimPrefix(manifestField, "Implementation-Version:")
		case strings.HasPrefix(manifestField, "Implementation-Title:"):
			m.implementationTitle = strings.TrimPrefix(manifestField, "Implementation-Title:")
		case strings.HasPrefix(manifestField, "Implementation-Vendor:"):
			m.implementationVendor = strings.TrimPrefix(manifestField, "Implementation-Vendor:")
		case strings.HasPrefix(manifestField, "Implementation-Vendor-Id:"):
			m.implementationVendorId = strings.TrimPrefix(manifestField, "Implementation-Vendor-Id:")
		case strings.HasPrefix(manifestField, "Specification-Version:"):
			m.specificationVersion = strings.TrimPrefix(manifestField, "Specification-Version:")
		case strings.HasPrefix(manifestField, "Specification-Title:"):
			m.specificationTitle = strings.TrimPrefix(manifestField, "Specification-Title:")
		case strings.HasPrefix(manifestField, "Specification-Vendor:"):
			m.specificationVendor = strings.TrimPrefix(manifestField, "Specification-Vendor:")
		case strings.HasPrefix(manifestField, "Bundle-Version:"):
			m.bundleVersion = strings.TrimPrefix(manifestField, "Bundle-Version:")
		case strings.HasPrefix(manifestField, "Bundle-Name:"):
			m.bundleName = strings.TrimPrefix(manifestField, "Bundle-Name:")
		case strings.HasPrefix(manifestField, "Bundle-SymbolicName:"):
			m.bundleSymbolicName = strings.TrimPrefix(manifestField, "Bundle-SymbolicName:")
		case strings.HasPrefix(manifestField, "Bundle-License:"):
			m.bundleLicense = strings.TrimPrefix(manifestField, "Bundle-License:")
		}
	}

	if err = scanner.Err(); err != nil {
		return manifest{}, xerrors.Errorf("scan error: %w", err)
	}
	return m, nil
}

func (m manifest) properties() Properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return Properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return Properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return Properties{}
	}
	// dont fail on the empty license
	return Properties{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		License:    m.bundleLicense,
	}
}

func (m manifest) determineGroupID() (string, error) {
	var groupID string
	switch {
	case m.implementationVendorId != "":
		groupID = m.implementationVendorId
	case m.bundleSymbolicName != "":
		groupID = m.bundleSymbolicName

		// e.g. "com.fasterxml.jackson.core.jackson-databind" => "com.fasterxml.jackson.core"
		idx := strings.LastIndex(m.bundleSymbolicName, ".")
		if idx > 0 {
			groupID = m.bundleSymbolicName[:idx]
		}
	case m.bundleName != "":
		groupID = m.bundleSymbolicName

		// e.g. "com.fasterxml.jackson.core.jackson-databind" => "com.fasterxml.jackson.core"
		idx := strings.LastIndex(m.bundleName, ".")
		if idx > 0 {
			groupID = m.bundleName[:idx]
		}
	case m.implementationVendor != "":
		groupID = m.implementationVendor
	case m.specificationVendor != "":
		groupID = m.specificationVendor
	default:
		return "", xerrors.New("no groupID found")
	}
	return strings.TrimSpace(groupID), nil
}

func (m manifest) determineArtifactID() (string, error) {
	var artifactID string
	switch {
	case m.bundleName != "":
		idx := strings.LastIndex(m.bundleName, ".")
		if idx > 0 {
			artifactID = m.bundleName[idx+1:]
		}
	case m.implementationTitle != "":
		artifactID = m.implementationTitle
	case m.specificationTitle != "":
		artifactID = m.specificationTitle

	default:
		return "", xerrors.New("no artifactID found")
	}
	return strings.TrimSpace(artifactID), nil
}

func (m manifest) determineVersion() (string, error) {
	var version string
	switch {
	case m.implementationVersion != "":
		version = m.implementationVersion
	case m.specificationVersion != "":
		version = m.specificationVersion
	case m.bundleVersion != "":
		version = m.bundleVersion
	default:
		return "", xerrors.New("no version found")
	}
	return strings.TrimSpace(version), nil
}
