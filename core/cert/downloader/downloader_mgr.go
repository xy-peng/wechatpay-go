package downloader

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"

	"github.com/wechatpay-apiv3/wechatpay-go/core"
	"github.com/wechatpay-apiv3/wechatpay-go/core/cert"
	"github.com/wechatpay-apiv3/wechatpay-go/utils/task"
)

const (
	// DefaultDownloadInterval 默认微信支付平台证书更新间隔
	DefaultDownloadInterval = 24 * time.Hour
)

type pseudoCertificateDownloader struct {
	mgr   *CertificateDownloaderMgr
	mchID string
}

func (o *pseudoCertificateDownloader) GetAll(ctx context.Context) map[string]*x509.Certificate {
	return o.mgr.GetCertificateMap(ctx, o.mchID)
}

func (o *pseudoCertificateDownloader) Get(ctx context.Context, serialNo string) (*x509.Certificate, bool) {
	return o.mgr.GetCertificate(ctx, o.mchID, serialNo)
}

func (o *pseudoCertificateDownloader) GetNewestSerial(ctx context.Context) string {
	return o.mgr.GetNewestCertificateSerial(ctx, o.mchID)
}

func (o *pseudoCertificateDownloader) ExportAll(ctx context.Context) map[string]string {
	return o.mgr.ExportCertificateMap(ctx, o.mchID)
}

func (o *pseudoCertificateDownloader) Export(ctx context.Context, serialNo string) (string, bool) {
	return o.mgr.ExportCertificate(ctx, o.mchID, serialNo)
}

// CertificateDownloaderMgr 证书下载器管理器
// 可挂载证书下载器 CertificateDownloader，会定时调用 CertificateDownloader 下载最新的证书
//
// CertificateDownloaderMgr 不会被 GoGC 自动回收，不再使用时应调用 Stop 方法，防止发生资源泄漏
type CertificateDownloaderMgr struct {
	ctx           context.Context
	task          *task.RepeatedTask
	downloaderMap map[string]*CertificateDownloader
	lock          sync.Mutex
}

func (o *CertificateDownloaderMgr) Stop() {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.task.Stop()
}

func (o *CertificateDownloaderMgr) GetCertificate(ctx context.Context, mchID, serialNo string) (
	*x509.Certificate, bool,
) {
	o.lock.Lock()
	downloader, ok := o.downloaderMap[mchID]
	o.lock.Unlock()

	if !ok {
		return nil, false
	}

	return downloader.Get(ctx, serialNo)
}

func (o *CertificateDownloaderMgr) GetCertificateMap(ctx context.Context, mchID string) map[string]*x509.Certificate {
	o.lock.Lock()
	downloader, ok := o.downloaderMap[mchID]
	o.lock.Unlock()

	if !ok {
		return nil
	}
	return downloader.GetAll(ctx)
}

func (o *CertificateDownloaderMgr) GetNewestCertificateSerial(ctx context.Context, mchID string) string {
	o.lock.Lock()
	downloader, ok := o.downloaderMap[mchID]
	o.lock.Unlock()

	if !ok {
		return ""
	}
	return downloader.GetNewestSerial(ctx)
}

func (o *CertificateDownloaderMgr) ExportCertificate(ctx context.Context, mchID, serialNo string) (string, bool) {
	o.lock.Lock()
	downloader, ok := o.downloaderMap[mchID]
	o.lock.Unlock()

	if !ok {
		return "", false
	}

	return downloader.Export(ctx, serialNo)
}

func (o *CertificateDownloaderMgr) ExportCertificateMap(ctx context.Context, mchID string) map[string]string {
	o.lock.Lock()
	downloader, ok := o.downloaderMap[mchID]
	o.lock.Unlock()

	if !ok {
		return nil
	}
	return downloader.ExportAll(ctx)
}

func (o *CertificateDownloaderMgr) GetCertificateVisitor(mchID string) cert.CertificateVisitor {
	return &pseudoCertificateDownloader{mgr: o, mchID: mchID}
}

func (o *CertificateDownloaderMgr) getTickHandler() func(time.Time) {
	return func(time.Time) {
		o.DownloadCertificates(o.ctx)
	}
}

func (o *CertificateDownloaderMgr) DownloadCertificates(ctx context.Context) {
	tmpDownloaderMap := make(map[string]*CertificateDownloader)

	o.lock.Lock()
	for key, downloader := range o.downloaderMap {
		tmpDownloaderMap[key] = downloader
	}
	o.lock.Unlock()

	for _, downloader := range tmpDownloaderMap {
		_ = downloader.DownloadCertificates(ctx)
	}
}

func (o *CertificateDownloaderMgr) RegisterDownloaderWithPrivateKey(
	ctx context.Context, privateKey *rsa.PrivateKey,
	certificateSerialNo string, mchID string, mchAPIv3Key string,
) error {
	downloader, err := NewCertificateDownloader(ctx, mchID, privateKey, certificateSerialNo, mchAPIv3Key)
	if err != nil {
		return err
	}

	o.lock.Lock()
	defer o.lock.Unlock()

	o.downloaderMap[mchID] = downloader
	return nil
}

func (o *CertificateDownloaderMgr) RegisterDownloaderWithClient(
	ctx context.Context, client *core.Client, mchID string, mchAPIv3Key string,
) error {
	downloader, err := NewCertificateDownloaderWithClient(ctx, client, mchAPIv3Key)
	if err != nil {
		return err
	}

	o.lock.Lock()
	defer o.lock.Unlock()

	o.downloaderMap[mchID] = downloader
	return nil
}

func (o *CertificateDownloaderMgr) RemoveDownloader(_ context.Context, mchID string) *CertificateDownloader {
	o.lock.Lock()
	defer o.lock.Unlock()

	downloader, ok := o.downloaderMap[mchID]
	if !ok {
		return nil
	}

	delete(o.downloaderMap, mchID)
	return downloader
}

// NewCertificateDownloaderMgr 以默认间隔 DefaultDownloadInterval 创建证书下载管理器
// 该管理器将以 DefaultDownloadInterval 的间隔定期调度所有 Downloader 进行证书下载。
// 证书管理器一旦创建即启动，使用完毕请调用 Stop() 防止发生资源泄漏
func NewCertificateDownloaderMgr(ctx context.Context) *CertificateDownloaderMgr {
	return NewCertificateDownloaderMgrWithInterval(ctx, DefaultDownloadInterval)
}

// NewCertificateDownloaderMgrWithInterval 创建一个空证书下载管理器（自定义更新间隔）
//
// 更新间隔最大不建议超过 2 天，以免错过平台证书平滑切换窗口；
// 同时亦不建议小于 1 小时，以避免过多请求导致浪费
func NewCertificateDownloaderMgrWithInterval(
	ctx context.Context, downloadInterval time.Duration,
) *CertificateDownloaderMgr {
	if downloadInterval <= 0 {
		downloadInterval = DefaultDownloadInterval
	}

	downloader := CertificateDownloaderMgr{
		ctx: ctx,
		downloaderMap: make(map[string]*CertificateDownloader),
	}
	downloader.task = task.NewRepeatedTask(downloadInterval, downloader.getTickHandler())
	downloader.task.Start()
	return &downloader
}
