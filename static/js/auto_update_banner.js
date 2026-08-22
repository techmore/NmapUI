let countdownInterval = null;
let remainingSeconds = 30;
let bannerVisible = false;
let autoUpdateSocket = null;
let autoUpdateBannerInitialized = false;

function showAutoUpdateBanner(updateInfo) {
    if (bannerVisible) return;

    bannerVisible = true;
    remainingSeconds = 30;

    const descElement = document.getElementById('update-description');
    if (updateInfo.latest_version) {
        descElement.textContent = `NmapUI ${updateInfo.latest_version} is available to download`;
    }

    const banner = document.getElementById('auto-update-banner');
    banner.classList.remove('hidden');
    banner.style.animation = 'slideDown 0.5s ease-out';

    startCountdown();
}

function hideAutoUpdateBanner() {
    if (!bannerVisible) return;

    bannerVisible = false;
    clearInterval(countdownInterval);

    const banner = document.getElementById('auto-update-banner');
    banner.style.animation = 'slideUp 0.3s ease-in';
    setTimeout(() => {
        banner.classList.add('hidden');
        banner.style.animation = '';
    }, 300);
}

function startCountdown() {
    const timerElement = document.getElementById('countdown-timer');
    const progressBar = document.getElementById('progress-bar');

    countdownInterval = setInterval(() => {
        remainingSeconds--;
        timerElement.textContent = remainingSeconds;

        const progressPercent = ((30 - remainingSeconds) / 30) * 100;
        progressBar.style.width = `${progressPercent}%`;

        if (remainingSeconds <= 0) {
            performAutoUpdate();
        }
    }, 1000);
}

function performAutoUpdate() {
    clearInterval(countdownInterval);
    autoUpdateSocket.emit('perform_app_update');
    hideAutoUpdateBanner();
}

function bindAutoUpdateButtons() {
    document.getElementById('update-now-btn')?.addEventListener('click', () => {
        performAutoUpdate();
    });

    document.getElementById('cancel-update-btn')?.addEventListener('click', () => {
        autoUpdateSocket.emit('cancel_auto_update');
        hideAutoUpdateBanner();
    });
}

function initializeAutoUpdateBanner(socket) {
    if (autoUpdateBannerInitialized) {
        return;
    }

    autoUpdateBannerInitialized = true;
    autoUpdateSocket = socket;

    socket.on('idle_state_changed', data => {
        console.log('Idle state changed:', data);
    });

    socket.on('show_auto_update_banner', data => {
        console.log('Showing auto-update banner:', data);
        showAutoUpdateBanner(data);
    });

    socket.on('hide_auto_update_banner', () => {
        console.log('Hiding auto-update banner');
        hideAutoUpdateBanner();
    });

    bindAutoUpdateButtons();
}

window.showAutoUpdateBanner = showAutoUpdateBanner;
window.hideAutoUpdateBanner = hideAutoUpdateBanner;
window.initializeAutoUpdateBanner = initializeAutoUpdateBanner;
