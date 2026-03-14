(function () {
    let initialized = false;

    function initializeMobileMenu() {
        const mobileMenuBtn = document.getElementById('mobile-menu-btn');
        const mobileMenu = document.getElementById('mobile-menu');

        if (!mobileMenuBtn || !mobileMenu) {
            return;
        }

        mobileMenuBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('hidden');
        });

        mobileMenu.querySelectorAll('a').forEach((link) => {
            link.addEventListener('click', () => {
                mobileMenu.classList.add('hidden');
            });
        });
    }

    function initializeSearch() {
        const searchInput = document.getElementById('global-search');

        if (!searchInput) {
            return;
        }

        searchInput.addEventListener('input', (event) => {
            const searchTerm = event.target.value.toLowerCase().trim();

            document.querySelectorAll('.compact-card').forEach((card) => {
                const title = card.querySelector('h3')?.textContent.toLowerCase() || '';
                const subtitle = card.querySelector('p')?.textContent.toLowerCase() || '';
                const meta = card.textContent.toLowerCase() || '';

                if (!searchTerm || title.includes(searchTerm) || subtitle.includes(searchTerm) || meta.includes(searchTerm)) {
                    card.style.display = '';
                    setTimeout(() => {
                        card.style.opacity = '1';
                    }, 10);
                } else {
                    card.style.opacity = '0';
                    setTimeout(() => {
                        card.style.display = 'none';
                    }, 150);
                }
            });
        });

        document.addEventListener('keydown', (event) => {
            if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
                event.preventDefault();
                searchInput.focus();
                searchInput.select();
            }

            if (event.key === 'Escape') {
                const mobileMenu = document.getElementById('mobile-menu');
                if (mobileMenu) {
                    mobileMenu.classList.add('hidden');
                }
                searchInput.blur();
            }
        });
    }

    function initializeFilterPills() {
        const filterPills = document.querySelectorAll('.filter-pill');

        filterPills.forEach((pill) => {
            pill.addEventListener('click', () => {
                const parent = pill.parentElement;
                if (parent) {
                    parent.querySelectorAll('.filter-pill').forEach((sibling) => {
                        sibling.classList.remove('active', 'bg-olive-600', 'text-white');
                        sibling.classList.add('text-stone-600');
                        if (!sibling.classList.contains('bg-white') && !sibling.classList.contains('border')) {
                            sibling.classList.add('text-stone-600');
                        }
                    });
                }

                pill.classList.add('active');
                pill.classList.remove('text-stone-600');

                if (pill.querySelector('svg')) {
                    pill.classList.add('bg-olive-600', 'text-white');
                }

                const filter = pill.getAttribute('data-filter');
                if (filter && filter !== 'all') {
                    document.querySelectorAll('.compact-card').forEach((card) => {
                        const cardText = card.textContent.toLowerCase();
                        let matches = false;

                        if (filter === 'books' && (cardText.includes('book') || cardText.includes('press') || cardText.includes('pp'))) matches = true;
                        else if (filter === 'video' && (cardText.includes('video') || cardText.includes('movie') || cardText.includes('hbo') || cardText.includes('bbc') || cardText.includes('eps') || cardText.includes('m'))) matches = true;
                        else if (filter === 'research' && (cardText.includes('pdf') || cardText.includes('paper') || cardText.includes('journal') || cardText.includes('et al') || cardText.includes('cites'))) matches = true;
                        else if (filter === 'audio' && (cardText.includes('audio') || cardText.includes('podcast') || cardText.includes('headphones') || cardText.includes('h'))) matches = true;
                        else if (filter === 'photos' && (cardText.includes('photo') || cardText.includes('collection') || cardText.includes('natgeo'))) matches = true;

                        if (matches) {
                            card.style.display = '';
                            setTimeout(() => {
                                card.style.opacity = '1';
                            }, 10);
                        } else {
                            card.style.opacity = '0';
                            setTimeout(() => {
                                card.style.display = 'none';
                            }, 200);
                        }
                    });
                } else if (filter === 'all') {
                    document.querySelectorAll('.compact-card').forEach((card) => {
                        card.style.display = '';
                        setTimeout(() => {
                            card.style.opacity = '1';
                        }, 10);
                    });
                }
            });
        });
    }

    function initializeCompactCards() {
        document.querySelectorAll('.compact-card').forEach((card) => {
            card.addEventListener('click', () => {
                card.style.transform = 'scale(0.98)';
                setTimeout(() => {
                    card.style.transform = '';
                }, 150);
            });
        });

        document.querySelectorAll('.compact-card button').forEach((button) => {
            button.addEventListener('click', (event) => {
                event.stopPropagation();
                const isAdded = button.classList.contains('bg-olive-600');

                if (!isAdded) {
                    button.classList.add('bg-olive-600', 'text-white');
                    button.classList.remove('bg-white');
                    button.innerHTML = '<i data-lucide="check" class="w-4 h-4"></i>';
                } else {
                    button.classList.remove('bg-olive-600', 'text-white');
                    button.classList.add('bg-white');
                    button.innerHTML = '<i data-lucide="plus" class="w-4 h-4 text-olive-700"></i>';
                }

                if (window.lucide?.createIcons) {
                    window.lucide.createIcons();
                }

                button.style.transform = 'scale(1.2)';
                setTimeout(() => {
                    button.style.transform = '';
                }, 200);
            });
        });
    }

    function initializeLazyImages() {
        if (!('IntersectionObserver' in window)) {
            return;
        }

        const imageObserver = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    return;
                }

                const image = entry.target;
                image.classList.add('opacity-0');
                setTimeout(() => {
                    image.classList.remove('opacity-0');
                    image.classList.add('transition-opacity', 'duration-500');
                }, 50);
                imageObserver.unobserve(image);
            });
        }, { rootMargin: '50px' });

        document.querySelectorAll('img').forEach((image) => {
            imageObserver.observe(image);
        });
    }

    function initializeLoadMore() {
        const loadMoreBtn = document.querySelector('button:not([onclick])');
        if (!loadMoreBtn || !loadMoreBtn.textContent.includes('Load More')) {
            return;
        }

        loadMoreBtn.addEventListener('click', function () {
            const originalText = this.textContent;
            this.innerHTML = '<span class="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></span> Loading...';
            this.disabled = true;

            setTimeout(() => {
                this.textContent = originalText;
                this.disabled = false;
            }, 800);
        });
    }

    function initializeScrollContent() {
        window.scrollContent = function (gridId, direction) {
            const grid = document.getElementById(`${gridId}-grid`);
            if (grid) {
                grid.scrollBy({ left: direction * 300, behavior: 'smooth' });
            }
        };
    }

    function initializeSiteChrome() {
        if (initialized) {
            return;
        }

        initialized = true;
        initializeMobileMenu();
        initializeSearch();
        initializeFilterPills();
        initializeScrollContent();
        initializeCompactCards();
        initializeLazyImages();
        initializeLoadMore();
    }

    window.initializeSiteChrome = initializeSiteChrome;
})();
