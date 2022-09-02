	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
func RepoPath(ctx context.Context, source string, head string) (chan Commit, error) {
		FromReader(ctx, stdOut, commitChan)
		if err := cmd.Wait(); err != nil {
			log.WithError(err).Debugf("Error waiting for git command to complete.")
		}
	}()

	return commitChan, nil
}

func FromReader(ctx context.Context, stdOut io.Reader, commitChan chan Commit) {
	outReader := bufio.NewReader(stdOut)
	var currentCommit *Commit
	var currentDiff *Diff

	defer common.Recover(ctx)
	for {
		line, err := outReader.ReadBytes([]byte("\n")[0])
		if err != nil && len(line) == 0 {
			break
		}
		switch {
		case isCommitLine(line):
			// If there is a currentDiff, add it to currentCommit.
			if currentDiff != nil && currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
			}
			// If there is a currentCommit, send it to the channel.
			if currentCommit != nil {
				commitChan <- *currentCommit
			}
			// Create a new currentDiff and currentCommit
			currentDiff = &Diff{}
			currentCommit = &Commit{
				Message: strings.Builder{},
			}
			// Check that the commit line contains a hash and set it.
			if len(line) >= 47 {
				currentCommit.Hash = string(line[7:47])
			}
		case isAuthorLine(line):
			currentCommit.Author = string(line[8:])
		case isDateLine(line):
			date, err := time.Parse(DateFormat, strings.TrimSpace(string(line[6:])))
			if err != nil {
				log.WithError(err).Debug("Could not parse date from git stream.")
			}
			currentCommit.Date = date
		case isDiffLine(line):
			// This should never be nil, but check in case the stdin stream is messed up.
			if currentDiff != nil && currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
			}
			currentDiff = &Diff{}
		case isModeLine(line):
			// NoOp
		case isIndexLine(line):
			// NoOp
		case isPlusFileLine(line):
			currentDiff.PathB = strings.TrimRight(string(line[6:]), "\n")
		case isMinusFileLine(line):
			// NoOp
		case isPlusDiffLine(line):
			currentDiff.Content.Write(line[1:])
		case isMinusDiffLine(line):
			// NoOp. We only care about additions.
		case isMessageLine(line):
			currentCommit.Message.Write(line[4:])
		case isBinaryLine(line):
			currentDiff.IsBinary = true
			currentDiff.PathB = pathFromBinaryLine(line)
		case isLineNumberDiffLine(line):
			if currentDiff != nil && currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
			}
			newDiff := &Diff{
				PathB: currentDiff.PathB,
			currentDiff = newDiff
			words := bytes.Split(line, []byte(" "))
			if len(words) >= 3 {
				startSlice := bytes.Split(words[2], []byte(","))
				lineStart, err := strconv.Atoi(string(startSlice[0]))
				if err == nil {
					currentDiff.LineStart = lineStart

	}
	if currentDiff != nil && currentDiff.Content.Len() > 0 {
		currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
	}
	if currentCommit != nil {
		commitChan <- *currentCommit
	}
	close(commitChan)
	if len(line) >= 6 && bytes.Equal(line[:3], []byte("---")) {
	if len(line) >= 6 && bytes.Equal(line[:3], []byte("+++")) {