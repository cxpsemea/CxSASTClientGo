package CxSASTClientGo

import (
	"encoding/json"
)

func (c SASTClient) GetIssueTrackers() ([]IssueTracker, error) {
	var trackers []IssueTracker
	response, err := c.getV("/issueTrackingSystems", "1.0")

	if err != nil {
		return trackers, err
	}

	err = json.Unmarshal(response, &trackers)
	return trackers, err
}

func (c SASTClient) GetCustomTasks() ([]CustomTask, error) {
	var tasks []CustomTask
	response, err := c.getV("/customTasks", "1.0")

	if err != nil {
		return tasks, err
	}

	err = json.Unmarshal(response, &tasks)
	return tasks, err
}
