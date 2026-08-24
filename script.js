const searchInput = document.getElementById("searchInput");
const searchButton = document.getElementById("searchButton");
const searchResults = document.getElementById("searchResults");

async function searchMovies() {

    const query = searchInput.value.trim().toLowerCase();

    searchResults.innerHTML = "";

    if (query === "") {
        searchResults.innerHTML = "<p>Please enter a movie name.</p>";
        return;
    }

    try {

        const response = await fetch("http://127.0.0.1:8000/movies");

        const data = await response.json();

        const results = data.movies.filter(movie =>
            movie.title.toLowerCase().includes(query)
        );

        if (results.length === 0) {
            searchResults.innerHTML = "<p>No movies found.</p>";
            return;
        }

        results.forEach(movie => {

            const result = document.createElement("div");

            result.className = "search-result";

          const moviePage = `movie.html?id=${movie.id}`;

result.innerHTML = `
    <a href="${moviePage}">
        <strong>🎬 ${movie.title}</strong>
        <span>${movie.language} • ${movie.release_date}</span>
        <br>
        <span>⭐ ${movie.verdict}</span>
        <br>
        <span>Worldwide: ₹${movie.worldwide_collection_crore} Cr</span>
    </a>
`;

            searchResults.appendChild(result);

        });

    } catch (error) {

        console.error(error);

        searchResults.innerHTML =
            "<p>Unable to connect to BoxOfficeX server.</p>";
    }
}

searchButton.addEventListener("click", searchMovies);

searchInput.addEventListener("keydown", function(event) {

    if (event.key === "Enter") {
        searchMovies();
    }

});
